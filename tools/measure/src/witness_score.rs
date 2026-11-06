use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::Path,
    process::Command as ProcessCommand,
};

use serde_json::{json, Value};

const MATRIX_TRANSPORTS: &[&str] = &["https_ws", "grpc_stream"];
const MATRIX_PROFILES: &[&str] = &[
    "clean_fiber",
    "mobile_peak",
    "congested_wifi",
    "slow_mobile",
    "middlebox_delay",
];
const FULL_PASS_THRESHOLD: f64 = 0.85;

const TSHARK_BASE_FIELDS: &[&str] = &[
    "frame.time_epoch",
    "frame.len",
    "ip.src",
    "ip.dst",
    "ipv6.src",
    "ipv6.dst",
    "tcp.srcport",
    "tcp.dstport",
];

const TSHARK_FINGERPRINT_FIELDS: &[&str] = &[
    "frame.number",
    "tls.handshake.ja3",
    "tls.handshake.ja3_full",
    "tls.handshake.ja4",
    "tls.handshake.ja4_r",
    "tls.handshake.extensions_server_name",
    "tls.handshake.extensions_alpn_str",
];

#[derive(Clone, Debug)]
struct PacketRow {
    ts_ms: i64,
    frame_len: u64,
    src_port: Option<u16>,
    dst_port: Option<u16>,
}

#[derive(Clone, Debug)]
struct SeriesSummary {
    min: u64,
    max: u64,
    mean: f64,
    p50: u64,
    p90: u64,
    p99: u64,
}

#[derive(Clone, Debug, Default)]
struct TlsFingerprint {
    client_hello_seen: bool,
    ja3_hash: Option<String>,
    ja3_full: Option<String>,
    ja4_fingerprint: Option<String>,
    ja4_r: Option<String>,
    sni: Option<String>,
    alpn: Option<String>,
}

pub struct WitnessScoreInput<'a> {
    pub transport: &'a str,
    pub netem_profile: &'a str,
    pub pcap_path: &'a Path,
    pub runtime_events: &'a [Value],
    pub ndpi_summary: &'a Value,
    pub suricata_summary: &'a Value,
    pub reference_profile: Option<&'a Value>,
    pub tshark_bin: &'a str,
}

pub struct ReferencePcapInput<'a> {
    pub artifact: &'a str,
    pub transport: &'a str,
    pub netem_profile: &'a str,
    pub client_type: &'a str,
    pub endpoint_url: &'a str,
    pub provider: &'a str,
    pub pcap_path: &'a Path,
    pub ndpi_summary: &'a Value,
    pub suricata_summary: &'a Value,
    pub tshark_bin: &'a str,
    /// The fingerprints this capture is expected to carry.
    ///
    /// A reference profile exists to say "this is what a browser looks like on
    /// this path". Measuring its JA3/JA4 and never checking them proves the
    /// capture parsed, not that it came from the browser it claims. Supplying
    /// the expected values — from the recorded live-Chrome capture, not from a
    /// constant in this file, which would rot on the next Chrome release —
    /// turns the profile into a verified baseline.
    pub expected_ja3: Option<&'a str>,
    pub expected_ja4: Option<&'a str>,
}

pub fn witness_score(input: WitnessScoreInput<'_>) -> Value {
    let expected = canonical_transport(input.transport);
    let (runtime_selected, relay_session_succeeded, fallback_transports_seen) =
        selected_and_succeeded(input.runtime_events, &expected);
    let runtime_linked = runtime_selected && relay_session_succeeded;
    let pcap_present =
        input.pcap_path.exists() && input.pcap_path.metadata().map(|m| m.len()).unwrap_or(0) > 0;
    let pcap_metrics = if pcap_present {
        tshark_packet_rows(input.pcap_path, input.tshark_bin).ok()
    } else {
        None
    };
    let tls_fingerprint = if pcap_present {
        tshark_tls_fingerprint(input.pcap_path, input.tshark_bin).unwrap_or_default()
    } else {
        TlsFingerprint::default()
    };

    let ndpi_risk_count = number_from(input.ndpi_summary, &["risk_count", "ndpi_risk_count"]);
    let suricata_alert_count = number_from(
        input.suricata_summary,
        &["alert_count", "suricata_alert_count"],
    );
    // What counts as "clean" is what the BROWSER REFERENCE looks like, not zero.
    //
    // nDPI flags live Chrome 151 with `TLS Suspicious Extension` on its own
    // flows — its opinion of GREASE/ECH, which every modern browser sends.
    // Measured side by side on one host: Chrome risk_count 2, ours 1. Scoring
    // any nonzero risk as a tell therefore blocked the KPI for traffic flagged
    // LESS than the browser it imitates, which is the goal rather than a
    // failure. Same error the active-probe metric had: it asked "are you
    // invisible" when the question is "are you a browser".
    //
    // Falls back to the strict zero test when no reference is available, so a
    // run without a browser baseline cannot quietly grade itself easier.
    let reference_ndpi_risk = input
        .reference_profile
        .and_then(|reference| number_from(reference, &["risk_count", "ndpi_risk_count"]));
    let reference_suricata_alerts = input
        .reference_profile
        .and_then(|reference| number_from(reference, &["alert_count", "suricata_alert_count"]));
    let within_reference = |ours: Option<u64>, reference: Option<u64>| match (ours, reference) {
        (Some(ours), Some(reference)) => ours <= reference,
        (Some(ours), None) => ours == 0,
        _ => false,
    };
    let classifier_clean = within_reference(ndpi_risk_count, reference_ndpi_risk)
        && within_reference(suricata_alert_count, reference_suricata_alerts);
    // Three-valued for scoring: a classifier that never ran is NOT a dirty
    // verdict. Collapsing "not measured" into `false` scored the 0.30-weight
    // term at zero and dragged the KPI down for a capture nobody had run nDPI
    // or Suricata over — a false negative dressed up as a measurement.
    // Any classifier that DID run and DID flag something makes the verdict
    // dirty, even if the other one never ran. Requiring both to be present
    // before forming a verdict meant a single nDPI run reporting risks was
    // reported as NOT_MEASURED and dropped from the score — an alert we had in
    // hand, inflating the KPI.
    // Judged against the browser reference for the same reason `classifier_clean`
    // is. Leaving this on the zero test while the flag above moved made the two
    // disagree: a cell reported classifier_clean=true and still scored the
    // 0.30-weight classifier term at zero, holding every cell at exactly 0.70.
    let classifier_verdict: Option<bool> = match (ndpi_risk_count, suricata_alert_count) {
        (Some(_), Some(_)) => Some(classifier_clean),
        (Some(count), None) if !within_reference(Some(count), reference_ndpi_risk) => Some(false),
        (None, Some(count)) if !within_reference(Some(count), reference_suricata_alerts) => {
            Some(false)
        }
        _ => None,
    };

    let packet_count = pcap_metrics
        .as_ref()
        .map(|metrics| metrics.packet_count)
        .unwrap_or(0);
    let byte_count = pcap_metrics
        .as_ref()
        .map(|metrics| metrics.byte_count)
        .unwrap_or(0);
    let timing_present = pcap_metrics
        .as_ref()
        .and_then(|metrics| metrics.inter_arrival_ms_summary.as_ref())
        .is_some();
    let ratio_present = pcap_metrics
        .as_ref()
        .and_then(|metrics| metrics.upload_download_ratio)
        .is_some();
    let reference_status = reference_status(input.reference_profile);
    let reference_ready = matches!(reference_status.as_str(), "PASS" | "SCOPED_REFERENCE_READY");
    let reference_component_ready = match reference_status.as_str() {
        "PASS" | "SCOPED_REFERENCE_READY" => 1.0,
        // Same reason as the blocker label below: PARTIAL_REFERENCE_CAPTURED
        // is a captured-but-incomplete reference and should score as half,
        // not as nothing.
        status if status.starts_with("PARTIAL") => 0.5,
        _ => 0.0,
    };
    let ja3_status = if tls_fingerprint.ja3_hash.is_some() {
        "MEASURED"
    } else {
        "NOT_MEASURED"
    };
    let ja4_status = if tls_fingerprint.ja4_fingerprint.is_some() {
        "MEASURED"
    } else {
        "NOT_MEASURED"
    };

    let mut blockers = Vec::new();
    if !runtime_linked {
        blockers.push("runtime_linkage_missing");
    }
    if !fallback_transports_seen.is_empty() {
        blockers.push("fallback_transport_contamination");
    }
    if !pcap_present {
        blockers.push("relay_only_pcap_missing");
    } else if pcap_metrics.is_none() {
        blockers.push("pcap_parse_failed");
    }
    // Blocked when we look WORSE than the browser, not when we look non-zero.
    // Kept in step with `classifier_clean` above: these two disagreeing is how
    // a cell scored as classifier-clean while still reporting
    // `ndpi_risk_count_nonzero` as a blocker, which reads as a contradiction
    // to anyone holding the output.
    if ndpi_risk_count.is_none() {
        blockers.push("ndpi_risk_count_missing");
    } else if !within_reference(ndpi_risk_count, reference_ndpi_risk) {
        blockers.push(if reference_ndpi_risk.is_some() {
            "ndpi_risk_count_above_browser_reference"
        } else {
            "ndpi_risk_count_nonzero"
        });
    }
    if suricata_alert_count.is_none() {
        blockers.push("suricata_alert_count_missing");
    } else if !within_reference(suricata_alert_count, reference_suricata_alerts) {
        blockers.push(if reference_suricata_alerts.is_some() {
            "suricata_alert_count_above_browser_reference"
        } else {
            "suricata_alert_count_nonzero"
        });
    }
    if !timing_present {
        blockers.push("inter_arrival_timing_missing");
    }
    if !ratio_present {
        blockers.push("upload_download_ratio_missing");
    }
    if !reference_ready {
        blockers.push(match reference_status.as_str() {
            "BLOCKED_REFERENCE_TIMING_MISSING" => "reference_timing_baseline_missing",
            "BLOCKED_JA3_REFERENCE_MISSING" => "reference_ja3_missing",
            "BLOCKED_JA4_REFERENCE_MISSING" => "reference_ja4_missing",
            // Any PARTIAL* status means a reference WAS captured and is
            // incomplete. Matching the bare string only meant
            // `PARTIAL_REFERENCE_CAPTURED` fell through to "missing", which
            // sends whoever reads the blocker looking for a capture that is
            // sitting right there. Wrong label, wrong next action.
            status if status.starts_with("PARTIAL") => "reference_baseline_partial",
            _ => "reference_baseline_missing",
        });
    }
    if ja3_status != "MEASURED" {
        blockers.push("ja3_not_measured");
    }
    if ja4_status != "MEASURED" {
        blockers.push("ja4_not_measured");
    }
    // Measuring our own fingerprint proves nothing without a browser to
    // compare it to. The shipped corpus is curl and python-websockets, so this
    // blocker is currently expected — and it is the reason the KPI cannot be
    // quoted yet.
    let reference_tls_class = reference_tls_baseline_class(input.reference_profile);
    match reference_tls_class {
        "BROWSER" => {}
        "NON_BROWSER_CONTROLLED_ENDPOINT" => {
            blockers.push("reference_tls_baseline_is_not_a_browser")
        }
        _ => blockers.push("reference_tls_baseline_missing"),
    }

    let component_scores = component_scores(
        classifier_clean,
        timing_present,
        pcap_metrics.as_ref(),
        ja3_status,
        ja4_status,
        runtime_linked && fallback_transports_seen.is_empty(),
        reference_component_ready,
    );
    let weights = score_weights();
    // Honest name for the presence-weighted sum. It gates whether the capture is
    // usable at all; it says nothing about whether the traffic resembles a browser.
    let evidence_completeness_score = weighted_score(&component_scores, &weights);

    // The KPI the master plan actually tracks: resemblance to the reference,
    // computed only from comparisons. `None` when nothing comparable exists.
    let indistinguishability = indistinguishability_components(
        classifier_verdict,
        pcap_metrics.as_ref(),
        &tls_fingerprint,
        input.reference_profile,
    );
    let (witness_indistinguishability_score, indistinguishability_detail) =
        match &indistinguishability {
            Some((score, detail)) => (json!(score), detail.clone()),
            None => (Value::Null, Value::Null),
        };

    let score_status = if !runtime_linked || !pcap_present || pcap_metrics.is_none() {
        "BLOCKED"
    } else {
        match indistinguishability {
            // PASS now requires the resemblance score to clear the bar. A capture
            // can be complete and still be trivially distinguishable, which is
            // exactly the case the old scoring called PASS.
            Some((score, _)) if blockers.is_empty() && score >= FULL_PASS_THRESHOLD => "PASS",
            Some(_) => "PARTIAL",
            None => "INSUFFICIENT_EVIDENCE_NO_REFERENCE_COMPARISON",
        }
    };

    let next_action = match score_status {
        "PASS" => "none",
        "BLOCKED" => "collect_missing_relay_only_runtime_or_pcap_evidence",
        _ if !reference_ready => "collect_reference_baseline",
        // A reference exists but carries too few comparable fields. Telling the
        // reader to collect capture inputs points at the wrong side.
        "INSUFFICIENT_EVIDENCE_NO_REFERENCE_COMPARISON" => {
            "enrich_reference_profile_with_comparable_fingerprint_and_distributions"
        }
        _ => "fill_missing_witness_score_components",
    };

    let metrics = metrics_json(pcap_metrics.as_ref());
    json!({
        // v2: `witness_indistinguishability_score` is now comparison-derived and
        // nullable, and the old presence-weighted sum moved to
        // `evidence_completeness_score`. The bump is what tells a reader that a
        // v1 artifact's score means something else entirely.
        "artifact_schema": "http_like_witness_score_v2",
        "transport": input.transport,
        "expected_runtime_transport": expected,
        "netem_profile": input.netem_profile,
        "score_status": score_status,
        "witness_indistinguishability_score": witness_indistinguishability_score,
        "indistinguishability_components": indistinguishability_detail,
        // BROWSER / NON_BROWSER_CONTROLLED_ENDPOINT / NONE. Only a BROWSER
        // baseline can supply a fingerprint worth matching.
        "reference_tls_baseline_class": reference_tls_class,
        // Kept, but under its true name: this is "did we collect the inputs",
        // not "does the traffic resemble a browser".
        "evidence_completeness_score": evidence_completeness_score,
        "thresholds": {
            "full_pass_min_witness_indistinguishability_score": FULL_PASS_THRESHOLD
        },
        "component_scores": component_scores,
        "weights": weights,
        "runtime_transport_selected": runtime_selected,
        "relay_session_succeeded": relay_session_succeeded,
        "runtime_linked": runtime_linked,
        "fallback_transports_seen": fallback_transports_seen,
        "pcap_present": pcap_present,
        "classifier_clean": classifier_clean,
        // MEASURED_CLEAN / MEASURED_DIRTY / NOT_MEASURED — so a reader can tell
        // "we ran nDPI and it was quiet" from "nobody ran nDPI".
        "classifier_evidence_status": match classifier_verdict {
            Some(true) => "MEASURED_CLEAN",
            Some(false) => "MEASURED_DIRTY",
            None => "NOT_MEASURED",
        },
        "ndpi_risk_count": ndpi_risk_count,
        "suricata_alert_count": suricata_alert_count,
        "packet_count": packet_count,
        "byte_count": byte_count,
        "upload_bytes": metrics["upload_bytes"].clone(),
        "download_bytes": metrics["download_bytes"].clone(),
        "upload_download_ratio": metrics["upload_download_ratio"].clone(),
        "packet_size_min": metrics["packet_size_min"].clone(),
        "packet_size_max": metrics["packet_size_max"].clone(),
        "packet_size_mean": metrics["packet_size_mean"].clone(),
        "packet_size_p50": metrics["packet_size_p50"].clone(),
        "packet_size_p90": metrics["packet_size_p90"].clone(),
        "packet_size_p99": metrics["packet_size_p99"].clone(),
        "inter_arrival_ms_min": metrics["inter_arrival_ms_min"].clone(),
        "inter_arrival_ms_max": metrics["inter_arrival_ms_max"].clone(),
        "inter_arrival_ms_mean": metrics["inter_arrival_ms_mean"].clone(),
        "inter_arrival_ms_p50": metrics["inter_arrival_ms_p50"].clone(),
        "inter_arrival_ms_p90": metrics["inter_arrival_ms_p90"].clone(),
        "inter_arrival_ms_p99": metrics["inter_arrival_ms_p99"].clone(),
        "burst_count": metrics["burst_count"].clone(),
        "session_duration_ms": metrics["session_duration_ms"].clone(),
        "client_to_relay_packet_count": metrics["client_to_relay_packet_count"].clone(),
        "relay_to_client_packet_count": metrics["relay_to_client_packet_count"].clone(),
        "ja3_status": ja3_status,
        "ja3_hash": tls_fingerprint.ja3_hash,
        "ja3_full": tls_fingerprint.ja3_full,
        "ja3_source": if ja3_status == "MEASURED" { "pcap_client_hello" } else { "not_available" },
        "ja4_status": ja4_status,
        "ja4_fingerprint": tls_fingerprint.ja4_fingerprint,
        "ja4_r": tls_fingerprint.ja4_r,
        "ja4_source": if ja4_status == "MEASURED" { "pcap_client_hello" } else { "not_available" },
        "tls_client_hello_seen": tls_fingerprint.client_hello_seen,
        "tls_alpn_observed": tls_fingerprint.alpn,
        "sni_status": if tls_fingerprint.sni.is_some() { "MEASURED" } else { "NOT_MEASURED" },
        "sni_observed": tls_fingerprint.sni,
        "reference_status": reference_status,
        "blockers": blockers,
        "next_action": next_action,
    })
}

pub fn witness_score_markdown(score: &Value) -> String {
    format!(
        "# Witness Score\n\n\
         - Transport: `{}`\n\
         - Netem profile: `{}`\n\
         - Score status: `{}`\n\
         - Witness indistinguishability score: `{}`\n\
         - Evidence completeness score: `{}`\n\
         - Runtime linked: `{}`\n\
         - Classifier clean: `{}`\n\
         - JA3: `{}`\n\
         - JA4: `{}`\n\
         - Reference status: `{}`\n\
         - Next action: `{}`\n",
        score["transport"].as_str().unwrap_or("unknown"),
        score["netem_profile"].as_str().unwrap_or("unknown"),
        score["score_status"].as_str().unwrap_or("UNKNOWN"),
        score["witness_indistinguishability_score"]
            .as_f64()
            .map(|value| format!("{value:.3}"))
            .unwrap_or_else(|| "null (no reference comparison available)".to_string()),
        score["evidence_completeness_score"]
            .as_f64()
            .map(|value| format!("{value:.3}"))
            .unwrap_or_else(|| "null".to_string()),
        score["runtime_linked"].as_bool().unwrap_or(false),
        score["classifier_clean"].as_bool().unwrap_or(false),
        score["ja3_status"].as_str().unwrap_or("UNKNOWN"),
        score["ja4_status"].as_str().unwrap_or("UNKNOWN"),
        score["reference_status"].as_str().unwrap_or("UNKNOWN"),
        score["next_action"].as_str().unwrap_or("unknown"),
    )
}

pub fn reference_pcap_score(input: ReferencePcapInput<'_>) -> Value {
    let pcap_present =
        input.pcap_path.exists() && input.pcap_path.metadata().map(|m| m.len()).unwrap_or(0) > 0;
    let pcap_metrics = if pcap_present {
        tshark_packet_rows(input.pcap_path, input.tshark_bin).ok()
    } else {
        None
    };
    let tls_fingerprint = if pcap_present {
        tshark_tls_fingerprint(input.pcap_path, input.tshark_bin).unwrap_or_default()
    } else {
        TlsFingerprint::default()
    };
    let metrics = metrics_json(pcap_metrics.as_ref());
    let ndpi_risk_count = number_from(input.ndpi_summary, &["risk_count", "ndpi_risk_count"]);
    let suricata_alert_count = number_from(
        input.suricata_summary,
        &["alert_count", "suricata_alert_count"],
    );
    // The reference IS the browser, so its own classifier counts ARE the
    // baseline — there is nothing above them to be dirty against. Requiring
    // zero made this blocker permanent: nDPI flags live Chrome 151 with
    // `TLS Suspicious Extension` on its own flows (GREASE/ECH), so a genuine
    // Chrome reference could never clear it, and every profile built from one
    // stayed PARTIAL forever. Record the counts; block only when a classifier
    // did not run at all, which is a real evidence gap.
    let classifier_counts_present = ndpi_risk_count.is_some() && suricata_alert_count.is_some();
    let ja3_measured = tls_fingerprint.ja3_hash.is_some();
    let ja4_measured = tls_fingerprint.ja4_fingerprint.is_some();
    let timing_present = pcap_metrics
        .as_ref()
        .and_then(|metrics| metrics.inter_arrival_ms_summary.as_ref())
        .is_some();
    let ratio_present = pcap_metrics
        .as_ref()
        .and_then(|metrics| metrics.upload_download_ratio)
        .is_some();

    let mut blockers = Vec::new();
    // Recorded and reported, never gating: things a reader should know that do
    // not make the reference unusable.
    let mut informational: Vec<&str> = Vec::new();
    if !pcap_present {
        blockers.push("reference_pcap_missing");
    } else if pcap_metrics.is_none() {
        blockers.push("reference_pcap_parse_failed");
    }
    if !classifier_counts_present {
        blockers.push("reference_classifier_counts_missing");
    }
    if !ja3_measured {
        blockers.push("ja3_not_measured");
    }
    if !ja4_measured {
        blockers.push("ja4_not_measured");
    }
    if !timing_present {
        blockers.push("inter_arrival_timing_missing");
    }
    if !ratio_present {
        blockers.push("upload_download_ratio_missing");
    }
    if input.provider != "cloudflare_fronted_path" {
        blockers.push("cloudflare_fronted_reference_path_missing");
    }

    // Compare the fingerprints instead of only measuring them.
    //
    // This used to be an unconditional `ja3_ja4_measured_but_not_compared`
    // blocker — a permanent TODO that held every reference profile at PARTIAL
    // forever, and with it every cell that used one. Measuring JA3/JA4 proves
    // the capture parsed. It does not prove the capture came from the browser
    // the profile claims, which is the entire job of a reference.
    //
    // Expected values come from the caller (the recorded live-Chrome capture),
    // never from a constant here: a hardcoded fingerprint would go stale on the
    // next Chrome release and start failing good references.
    let compare = |measured: Option<&str>, expected: Option<&str>| match (measured, expected) {
        (Some(measured), Some(expected)) => Some(measured.eq_ignore_ascii_case(expected)),
        _ => None,
    };
    let ja3_matches = compare(tls_fingerprint.ja3_hash.as_deref(), input.expected_ja3);
    let ja4_matches = compare(
        tls_fingerprint.ja4_fingerprint.as_deref(),
        input.expected_ja4,
    );
    // A JA3 mismatch beside a JA4 match is extension-order randomisation, not a
    // different client — and it must not gate.
    //
    // Chrome has shuffled its ClientHello extension order per connection since
    // 110. JA3 hashes the list in the order it appears; canonical JA4 sorts
    // first. Measured here: five captures of one Chrome under five netem
    // profiles produced FIVE distinct JA3 hashes and ONE identical JA4. So
    // pinning an expected JA3 for a modern browser cannot ever match, and
    // treating that as a failed reference blocked every profile built from a
    // genuine Chrome capture.
    //
    // The comparison stays for clients that do not randomise, where a JA3
    // mismatch is real information. It just stops being a verdict.
    match (ja3_matches, ja4_matches) {
        (Some(false), Some(true)) => {
            informational.push("reference_ja3_varies_by_connection_ja4_stable")
        }
        (Some(false), _) => blockers.push("reference_ja3_does_not_match_expected"),
        (None, _) if ja3_measured => informational.push("ja3_expected_value_not_supplied"),
        _ => {}
    }
    // A bare "does not match" sends the reader hunting for a mimicry gap that
    // may not exist. Canonical JA4 puts the SNI marker and the extension COUNT
    // in the head while deliberately keeping SNI out of the hashes, so a
    // capture against an IP literal reads `t13i1515h2` where the same client
    // against a domain reads `t13d1516h2` — different head, identical hashes,
    // same TLS stack. That difference already cost a wrong "mimicry gap" call
    // once (see 2026-08-11/quic-masque-ja4-parity). Name which part moved.
    match ja4_matches {
        Some(false) => blockers.push(
            match ja4_mismatch_part(
                tls_fingerprint.ja4_fingerprint.as_deref(),
                input.expected_ja4,
            ) {
                Ja4MismatchPart::HeadOnly => "reference_ja4_head_differs_hashes_match",
                Ja4MismatchPart::Hashes => "reference_ja4_does_not_match_expected",
            },
        ),
        None if ja4_measured => blockers.push("ja4_expected_value_not_supplied"),
        _ => {}
    }

    // One capture on one profile is still one sample. That stays a blocker, but
    // it no longer hides behind the comparison gap above.
    blockers.push("reference_profile_coverage_limited");

    // A reference whose fingerprints were checked and matched is usable as a
    // browser baseline even though its coverage is a single profile —
    // SCOPED_REFERENCE_READY is exactly that state, and witness_score treats it
    // as ready. Without a verified match it stays PARTIAL.
    // JA4 alone decides. A JA3 mismatch beside a JA4 match is extension-order
    // randomisation, which modern Chrome does on every connection — requiring
    // both meant a genuine browser reference could never verify.
    let fingerprints_verified = matches!(ja4_matches, Some(true))
        && !blockers
            .iter()
            .any(|blocker| *blocker != "reference_profile_coverage_limited");
    let verdict = if !pcap_present || pcap_metrics.is_none() {
        "BLOCKED_REFERENCE_PCAP_MISSING"
    } else if fingerprints_verified {
        "SCOPED_REFERENCE_READY"
    } else {
        "PARTIAL_REFERENCE_CAPTURED"
    };

    json!({
        "artifact": input.artifact,
        "verdict": verdict,
        "status": verdict,
        "transport": input.transport,
        "netem_profile": input.netem_profile,
        "client_type": input.client_type,
        "endpoint_url": input.endpoint_url,
        "provider": input.provider,
        "source": "controlled_reference_pcap_capture",
        "pcap_collected": pcap_present,
        "pcap_path": input.pcap_path.display().to_string(),
        "informational": informational,
        "expected_ja3": input.expected_ja3,
        "expected_ja4": input.expected_ja4,
        "ja3_matches_expected": ja3_matches,
        "ja4_matches_expected": ja4_matches,
        "sample_count": if pcap_present { 1 } else { 0 },
        "profiles_covered": if pcap_present { vec![input.netem_profile] } else { Vec::<&str>::new() },
        "packet_count": pcap_metrics.as_ref().map(|metrics| metrics.packet_count),
        "byte_count": pcap_metrics.as_ref().map(|metrics| metrics.byte_count),
        "upload_bytes": metrics["upload_bytes"].clone(),
        "download_bytes": metrics["download_bytes"].clone(),
        "upload_download_ratio": metrics["upload_download_ratio"].clone(),
        "packet_size_distribution": {
            "min": metrics["packet_size_min"].clone(),
            "max": metrics["packet_size_max"].clone(),
            "mean": metrics["packet_size_mean"].clone(),
            "p50": metrics["packet_size_p50"].clone(),
            "p90": metrics["packet_size_p90"].clone(),
            "p99": metrics["packet_size_p99"].clone(),
        },
        "inter_arrival_distribution": {
            "min": metrics["inter_arrival_ms_min"].clone(),
            "max": metrics["inter_arrival_ms_max"].clone(),
            "mean": metrics["inter_arrival_ms_mean"].clone(),
            "p50": metrics["inter_arrival_ms_p50"].clone(),
            "p90": metrics["inter_arrival_ms_p90"].clone(),
            "p99": metrics["inter_arrival_ms_p99"].clone(),
        },
        "session_duration_ms": metrics["session_duration_ms"].clone(),
        "burst_count": metrics["burst_count"].clone(),
        "ndpi_risk_count": ndpi_risk_count,
        "suricata_alert_count": suricata_alert_count,
        // Reported, never required: these counts define the baseline rather
        // than being measured against one.
        "classifier_counts_present": classifier_counts_present,
        "ja3_status": if ja3_measured { "MEASURED" } else { "NOT_MEASURED" },
        "ja3_hash": tls_fingerprint.ja3_hash,
        "ja3_full": tls_fingerprint.ja3_full,
        "ja3_source": if ja3_measured { "pcap_client_hello" } else { "not_available" },
        "ja4_status": if ja4_measured { "MEASURED" } else { "NOT_MEASURED" },
        "ja4_fingerprint": tls_fingerprint.ja4_fingerprint,
        "ja4_r": tls_fingerprint.ja4_r,
        "ja4_source": if ja4_measured { "pcap_client_hello" } else { "not_available" },
        "sni_status": if tls_fingerprint.sni.is_some() { "MEASURED" } else { "NOT_MEASURED" },
        "sni_observed": tls_fingerprint.sni,
        "tls_alpn_observed": tls_fingerprint.alpn,
        "blockers": blockers,
        "next_action": "capture_cloudflare_fronted_reference_and_compare_ja3_ja4",
    })
}

pub fn reference_pcap_score_markdown(score: &Value) -> String {
    format!(
        "# Reference PCAP Score\n\n\
         - Artifact: `{}`\n\
         - Verdict: `{}`\n\
         - Transport: `{}`\n\
         - Client type: `{}`\n\
         - PCAP collected: `{}`\n\
         - JA3: `{}`\n\
         - JA4: `{}`\n\
         - Classifier clean: `{}`\n\
         - Next action: `{}`\n",
        score["artifact"].as_str().unwrap_or("unknown"),
        score["verdict"].as_str().unwrap_or("UNKNOWN"),
        score["transport"].as_str().unwrap_or("unknown"),
        score["client_type"].as_str().unwrap_or("unknown"),
        score["pcap_collected"].as_bool().unwrap_or(false),
        score["ja3_status"].as_str().unwrap_or("UNKNOWN"),
        score["ja4_status"].as_str().unwrap_or("UNKNOWN"),
        score["classifier_clean"].as_bool().unwrap_or(false),
        score["next_action"].as_str().unwrap_or("unknown"),
    )
}

pub fn mimicry_matrix_review(matrix_root: &Path, reference_status: Option<&Value>) -> Value {
    let mut cells = Vec::new();
    let mut transport_summary = BTreeMap::<String, Value>::new();
    let mut profile_summary = BTreeMap::<String, Value>::new();
    let mut blockers = BTreeSet::<String>::new();
    let mut netem_profiles_covered = BTreeSet::<String>::new();
    let mut all_required_present = true;
    let mut any_useful = false;

    for transport in MATRIX_TRANSPORTS {
        let mut transport_pass = 0_u64;
        let mut transport_attempted = 0_u64;
        for profile in MATRIX_PROFILES {
            let cell_dir = matrix_root.join(transport).join(profile);
            let witness_path = cell_dir.join("witness-score.json");
            let result_path = cell_dir.join("result.json");
            let cell = read_cell(&witness_path, &result_path, transport, profile);
            let status = cell["verdict"].as_str().unwrap_or("BLOCKED");
            if status == "PASS" {
                transport_pass += 1;
            }
            if status != "MISSING" {
                transport_attempted += 1;
                any_useful = true;
                if cell["netem_profile"].as_str() == Some(*profile) {
                    netem_profiles_covered.insert((*profile).to_string());
                }
            }
            if status != "PASS" {
                all_required_present = false;
            }
            if !matches!(cell["ja3_status"].as_str(), Some("MEASURED") | Some("PASS")) {
                all_required_present = false;
                blockers.insert(format!("{transport}/{profile}:ja3_not_measured"));
            }
            if !matches!(cell["ja4_status"].as_str(), Some("MEASURED") | Some("PASS")) {
                all_required_present = false;
                blockers.insert(format!("{transport}/{profile}:ja4_not_measured"));
            }
            for blocker in cell["blockers"].as_array().into_iter().flatten() {
                if let Some(blocker) = blocker.as_str() {
                    blockers.insert(format!("{transport}/{profile}:{blocker}"));
                }
            }
            cells.push(cell);
        }
        transport_summary.insert(
            (*transport).to_string(),
            json!({
                "attempted_profiles": transport_attempted,
                "pass_profiles": transport_pass,
                "required_profiles": MATRIX_PROFILES.len(),
                "status": if transport_pass as usize == MATRIX_PROFILES.len() { "PASS" } else if transport_attempted > 0 { "PARTIAL" } else { "BLOCKED" },
            }),
        );
    }

    for profile in MATRIX_PROFILES {
        let mut attempted = 0_u64;
        let mut passed = 0_u64;
        for cell in &cells {
            if cell["netem_profile"].as_str() == Some(*profile)
                && cell["verdict"].as_str() != Some("MISSING")
            {
                attempted += 1;
                if cell["verdict"].as_str() == Some("PASS") {
                    passed += 1;
                }
            }
        }
        profile_summary.insert(
            (*profile).to_string(),
            json!({
                "attempted_transports": attempted,
                "pass_transports": passed,
                "required_transports": MATRIX_TRANSPORTS.len(),
                "status": if passed as usize == MATRIX_TRANSPORTS.len() { "PASS" } else if attempted > 0 { "PARTIAL" } else { "BLOCKED" },
            }),
        );
    }

    let reference_status_value = reference_status
        .and_then(|value| value.get("verdict").and_then(Value::as_str))
        .unwrap_or("NOT_PROVIDED");
    let reference_endpoint_missing = reference_status
        .and_then(|value| value.get("blockers"))
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .any(|blocker| blocker.contains("reference_endpoint_missing"));
    if !matches!(reference_status_value, "PASS" | "SCOPED_REFERENCE_READY") {
        blockers.insert("reference_baseline_not_pass".to_string());
    }

    let clean_fiber_only =
        netem_profiles_covered.len() == 1 && netem_profiles_covered.contains("clean_fiber");
    let clean_fiber_pass = cells
        .iter()
        .filter(|cell| {
            cell["netem_profile"].as_str() == Some("clean_fiber")
                && cell["verdict"].as_str() == Some("PASS")
        })
        .count()
        == MATRIX_TRANSPORTS.len();
    let matrix_verdict = if all_required_present && reference_status_value == "PASS" {
        "PASS"
    } else if all_required_present && reference_status_value == "SCOPED_REFERENCE_READY" {
        "SCOPED_PASS_REFERENCE_READY"
    } else if clean_fiber_only && clean_fiber_pass {
        "SCOPED_PASS"
    } else if any_useful {
        "PARTIAL"
    } else {
        "BLOCKED"
    };
    let ja3_status = aggregate_status(&cells, "ja3_status");
    let ja4_status = aggregate_status(&cells, "ja4_status");
    let next_action = if matches!(matrix_verdict, "PASS" | "SCOPED_PASS_REFERENCE_READY") {
        "brain_operational_live_calibrated_transport_proof"
    } else if reference_endpoint_missing {
        "create_controlled_websocket_grpc_reference_endpoints"
    } else if !matches!(reference_status_value, "PASS" | "SCOPED_REFERENCE_READY")
        && ja3_status == "MEASURED"
        && ja4_status == "MEASURED"
        && netem_profiles_covered.len() == MATRIX_PROFILES.len()
    {
        "expand_reference_timing_baseline"
    } else if matrix_verdict == "SCOPED_PASS" {
        "expand_netem_matrix_and_collect_reference_baseline"
    } else if matrix_verdict == "PARTIAL" {
        "fill_missing_reference_or_netem_or_ja3_ja4"
    } else {
        "collect_missing_relay_only_witness_evidence"
    };

    json!({
        "artifact_schema": "http_like_mimicry_matrix_review_v1",
        "artifact": "mimicry-http-like-witness-matrix",
        "verdict": matrix_verdict,
        "required_transports": MATRIX_TRANSPORTS,
        "required_profiles": MATRIX_PROFILES,
        "netem_profiles_covered": netem_profiles_covered.into_iter().collect::<Vec<_>>(),
        "reference_status": reference_status_value,
        "cells": cells,
        "per_transport_summary": transport_summary,
        "per_profile_summary": profile_summary,
        "ja3_status": ja3_status,
        "ja4_status": ja4_status,
        "timing_score_status": aggregate_bool_status(&cells, "timing_present"),
        "classifier_status": aggregate_bool_status(&cells, "classifier_clean"),
        "blockers": blockers.into_iter().collect::<Vec<_>>(),
        "next_action": next_action,
    })
}

pub fn mimicry_matrix_review_markdown(review: &Value) -> String {
    let mut out = String::new();
    out.push_str("# HTTP-like Mimicry Witness Matrix\n\n");
    out.push_str(&format!(
        "- Verdict: `{}`\n- Next action: `{}`\n- JA3 status: `{}`\n- JA4 status: `{}`\n\n",
        review["verdict"].as_str().unwrap_or("UNKNOWN"),
        review["next_action"].as_str().unwrap_or("unknown"),
        review["ja3_status"].as_str().unwrap_or("UNKNOWN"),
        review["ja4_status"].as_str().unwrap_or("UNKNOWN"),
    ));
    out.push_str(
        "| Transport | Profile | Verdict | nDPI risks | Suricata alerts | Witness score |\n",
    );
    out.push_str("|---|---|---:|---:|---:|---:|\n");
    for cell in review["cells"].as_array().into_iter().flatten() {
        out.push_str(&format!(
            "| `{}` | `{}` | `{}` | `{}` | `{}` | `{}` |\n",
            cell["transport"].as_str().unwrap_or("unknown"),
            cell["netem_profile"].as_str().unwrap_or("unknown"),
            cell["verdict"].as_str().unwrap_or("UNKNOWN"),
            cell["ndpi_risk_count"]
                .as_u64()
                .map(|value| value.to_string())
                .unwrap_or_else(|| "null".to_string()),
            cell["suricata_alert_count"]
                .as_u64()
                .map(|value| value.to_string())
                .unwrap_or_else(|| "null".to_string()),
            cell["witness_indistinguishability_score"]
                .as_f64()
                .map(|value| format!("{value:.3}"))
                .unwrap_or_else(|| "null".to_string()),
        ));
    }
    out
}

pub fn reference_timing_baseline(
    matrix_root: &Path,
    websocket_reference: Option<&Value>,
    grpc_reference: Option<&Value>,
    // A real browser capture. The websocket/grpc references are curl and
    // python-websockets — controlled endpoints, useful for traffic shape, but
    // their TLS fingerprints are not something we want to resemble. Only this
    // one can supply the fingerprint the witness score matches against.
    browser_reference: Option<&Value>,
) -> Value {
    let mut samples = Vec::new();
    let mut profiles = BTreeSet::new();
    let mut transports = BTreeSet::new();
    let mut packet_p50_values = Vec::new();
    let mut inter_arrival_p50_values = Vec::new();
    let mut ratios = Vec::new();
    let mut durations = Vec::new();

    for transport in MATRIX_TRANSPORTS {
        for profile in MATRIX_PROFILES {
            let path = matrix_root
                .join(transport)
                .join(profile)
                .join("witness-score.json");
            let Some(score) = fs::read_to_string(&path)
                .ok()
                .and_then(|text| serde_json::from_str::<Value>(&text).ok())
            else {
                continue;
            };
            if score["runtime_linked"].as_bool() != Some(true)
                || score["pcap_present"].as_bool() != Some(true)
            {
                continue;
            }
            profiles.insert((*profile).to_string());
            transports.insert((*transport).to_string());
            if let Some(value) = score["packet_size_p50"].as_u64() {
                packet_p50_values.push(value);
            }
            if let Some(value) = score["inter_arrival_ms_p50"].as_u64() {
                inter_arrival_p50_values.push(value);
            }
            if let Some(value) = score["upload_download_ratio"].as_f64() {
                ratios.push(value);
            }
            if let Some(value) = score["session_duration_ms"].as_u64() {
                durations.push(value);
            }
            samples.push(json!({
                "transport": transport,
                "profile": profile,
                "packet_size_p50": score["packet_size_p50"],
                "inter_arrival_ms_p50": score["inter_arrival_ms_p50"],
                "upload_download_ratio": score["upload_download_ratio"],
                "session_duration_ms": score["session_duration_ms"],
                "source_score": path.display().to_string(),
            }));
        }
    }

    let has_internal_metrics = !packet_p50_values.is_empty()
        && !inter_arrival_p50_values.is_empty()
        && !ratios.is_empty()
        && !durations.is_empty();

    let references = [
        ("websocket_reference", websocket_reference),
        ("grpc_reference", grpc_reference),
    ];
    let mut reference_summaries = Vec::new();
    let mut reference_blockers = BTreeSet::new();
    let mut ready_reference_count = 0_u64;
    let mut required_reference_count = 0_u64;
    let mut total_reference_samples = 0_u64;
    for (name, reference) in references {
        required_reference_count += 1;
        let Some(reference) = reference else {
            reference_blockers.insert(format!("{name}:reference_artifact_missing"));
            continue;
        };
        let verdict = reference_verdict(reference);
        let profiles = reference_profiles(reference);
        let sample_count = reference
            .get("sample_count")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        total_reference_samples += sample_count;
        if matches!(verdict.as_str(), "PASS" | "SCOPED_REFERENCE_READY") {
            ready_reference_count += 1;
        } else if verdict.contains("BLOCKED") {
            reference_blockers.insert(format!("{name}:reference_endpoint_missing"));
        } else {
            reference_blockers.insert(format!("{name}:reference_baseline_partial"));
        }
        // Carry the reference TLS fingerprints forward. Without them the
        // witness scorer has nothing to compare our ClientHello against, and
        // the fingerprint term silently drops out of the KPI.
        reference_summaries.push(json!({
            "name": name,
            "verdict": verdict,
            "client_type": reference.get("client_type").cloned().unwrap_or(Value::Null),
            "sample_count": sample_count,
            "profiles_covered": profiles,
            "source": reference.get("source").cloned().unwrap_or(Value::Null),
            "ja3_hash": reference.get("ja3_hash").cloned().unwrap_or(Value::Null),
            "ja4_fingerprint": reference.get("ja4_fingerprint").cloned().unwrap_or(Value::Null),
        }));
    }

    // The browser reference is tracked separately: it is the only source of a
    // fingerprint worth matching, and its absence is the reason the TLS term of
    // the witness score cannot be computed.
    let browser_reference_summary = browser_reference.map(|reference| {
        json!({
            "name": "browser_reference",
            "client_type": reference.get("client_type").cloned().unwrap_or(Value::Null),
            "browser_baseline": true,
            "ja3_hash": reference.get("ja3_hash").cloned().unwrap_or(Value::Null),
            "ja4_fingerprint": reference.get("ja4_fingerprint").cloned().unwrap_or(Value::Null),
            "source": reference.get("source").cloned().unwrap_or(Value::Null),
        })
    });
    if let Some(summary) = browser_reference_summary.clone() {
        reference_summaries.push(summary);
    } else {
        reference_blockers.insert("browser_reference_missing".to_string());
    }

    let all_references_ready = ready_reference_count == required_reference_count;
    let verdict = if all_references_ready {
        "SCOPED_REFERENCE_READY"
    } else if samples.is_empty() || !has_internal_metrics {
        "BLOCKED_REFERENCE_TIMING_MISSING"
    } else {
        "PARTIAL"
    };
    let mut limitations = vec![
        "controlled_internal_aegis_cloudflare_fronted_baseline_not_global_browser_baseline",
        "sample_count_limited",
        "ja3_ja4_reference_corpus_not_validated_as_browser_baseline",
    ];
    if !all_references_ready {
        limitations.push("separate_websocket_or_grpc_reference_endpoint_missing_or_limited");
    }
    json!({
        "artifact": "mimicry-reference-timing-baseline",
        "verdict": verdict,
        "status": if all_references_ready { "SCOPED_REFERENCE_READY" } else { "PARTIAL_REFERENCE_ENDPOINT_MISSING" },
        "baseline_id": "controlled_aegis_cloudflare_http_like_matrix_v1",
        "source": if all_references_ready { "controlled_websocket_grpc_reference_endpoints" } else { "existing_controlled_aegis_cloudflare_fronted_witness_matrix_plus_blocked_reference_endpoint_probe" },
        "sample_count": samples.len() as u64 + total_reference_samples,
        "internal_matrix_sample_count": samples.len(),
        "reference_endpoint_sample_count": total_reference_samples,
        "required_reference_count": required_reference_count,
        "ready_reference_count": ready_reference_count,
        "transports": transports.into_iter().collect::<Vec<_>>(),
        "profiles": profiles.into_iter().collect::<Vec<_>>(),
        "packet_size_distribution": summary_value(&packet_p50_values),
        "inter_arrival_distribution": summary_value(&inter_arrival_p50_values),
        "upload_download_ratio": f64_summary_value(&ratios),
        "session_duration": summary_value(&durations),
        "samples": samples,
        "reference_endpoints": reference_summaries,
        "browser_reference": browser_reference_summary,
        "tls_baseline_class": if browser_reference.is_some() { "BROWSER" } else { "NON_BROWSER_CONTROLLED_ENDPOINT" },
        "blockers": reference_blockers.into_iter().collect::<Vec<_>>(),
        "limitations": limitations,
        "next_action": if all_references_ready {
            "brain_operational_live_calibrated_transport_proof"
        } else if total_reference_samples > 0 {
            "capture_cloudflare_fronted_reference_and_compare_ja3_ja4"
        } else {
            "create_controlled_websocket_grpc_reference_endpoints"
        },
    })
}

pub fn reference_timing_baseline_markdown(baseline: &Value) -> String {
    format!(
        "# Mimicry Reference Timing Baseline\n\n\
         - Verdict: `{}`\n\
         - Baseline ID: `{}`\n\
         - Source: `{}`\n\
         - Sample count: `{}`\n\
         - Next action: `{}`\n\n\
         This is a controlled internal AEGIS Cloudflare-fronted baseline, not a global browser baseline.\n",
        baseline["verdict"].as_str().unwrap_or("UNKNOWN"),
        baseline["baseline_id"].as_str().unwrap_or("unknown"),
        baseline["source"].as_str().unwrap_or("unknown"),
        baseline["sample_count"].as_u64().unwrap_or(0),
        baseline["next_action"].as_str().unwrap_or("unknown"),
    )
}

fn read_cell(witness_path: &Path, result_path: &Path, transport: &str, profile: &str) -> Value {
    let mut blockers = Vec::new();
    let mut witness = fs::read_to_string(witness_path)
        .ok()
        .and_then(|text| serde_json::from_str::<Value>(&text).ok());
    if witness.is_none() {
        witness = fs::read_to_string(result_path)
            .ok()
            .and_then(|text| serde_json::from_str::<Value>(&text).ok());
    }
    let Some(witness) = witness else {
        return json!({
            "transport": transport,
            "netem_profile": profile,
            "verdict": "MISSING",
            "blockers": ["witness_score_missing"],
        });
    };
    if let Some(items) = witness.get("blockers").and_then(Value::as_array) {
        for item in items {
            if let Some(item) = item.as_str() {
                blockers.push(item.to_string());
            }
        }
    }
    let status = witness["score_status"].as_str().unwrap_or("BLOCKED");
    json!({
        "transport": witness["transport"].as_str().unwrap_or(transport),
        "netem_profile": witness["netem_profile"].as_str().unwrap_or(profile),
        "verdict": status,
        "runtime_linked": witness["runtime_linked"].as_bool().unwrap_or(false),
        "pcap_present": witness["pcap_present"].as_bool().unwrap_or(false),
        "classifier_clean": witness["classifier_clean"].as_bool().unwrap_or(false),
        "ndpi_risk_count": witness.get("ndpi_risk_count").cloned().unwrap_or(Value::Null),
        "suricata_alert_count": witness.get("suricata_alert_count").cloned().unwrap_or(Value::Null),
        "timing_present": witness.get("inter_arrival_ms_p50").is_some_and(|value| !value.is_null()),
        "ja3_status": witness["ja3_status"].as_str().unwrap_or("UNKNOWN"),
        "ja3_hash": witness.get("ja3_hash").cloned().unwrap_or(Value::Null),
        "ja4_status": witness["ja4_status"].as_str().unwrap_or("UNKNOWN"),
        "ja4_fingerprint": witness.get("ja4_fingerprint").cloned().unwrap_or(Value::Null),
        "witness_indistinguishability_score": witness.get("witness_indistinguishability_score").cloned().unwrap_or(Value::Null),
        "evidence_completeness_score": witness.get("evidence_completeness_score").cloned().unwrap_or(Value::Null),
        "blockers": blockers,
    })
}

#[derive(Clone, Debug)]
struct PcapMetrics {
    packet_count: u64,
    byte_count: u64,
    upload_bytes: u64,
    download_bytes: u64,
    upload_download_ratio: Option<f64>,
    packet_size_summary: Option<SeriesSummary>,
    inter_arrival_ms_summary: Option<SeriesSummary>,
    burst_count: u64,
    session_duration_ms: Option<u64>,
    client_to_relay_packet_count: u64,
    relay_to_client_packet_count: u64,
}

fn tshark_packet_rows(
    pcap: &Path,
    tshark_bin: &str,
) -> Result<PcapMetrics, Box<dyn std::error::Error>> {
    let mut command = ProcessCommand::new(tshark_bin);
    command.args([
        "-r",
        &pcap.display().to_string(),
        "-T",
        "fields",
        "-E",
        "header=n",
        "-E",
        "separator=\t",
        "-E",
        "occurrence=f",
    ]);
    for field in TSHARK_BASE_FIELDS {
        command.args(["-e", field]);
    }
    let output = command.output()?;
    if !output.status.success() {
        return Err(format!("tshark failed: {}", String::from_utf8_lossy(&output.stderr)).into());
    }
    let stdout = String::from_utf8(output.stdout)?;
    let mut packets = Vec::new();
    for raw_line in stdout.lines() {
        let mut parts = raw_line.split('\t').collect::<Vec<_>>();
        parts.resize(TSHARK_BASE_FIELDS.len(), "");
        let ts_ms = match parse_float(parts[0]) {
            Some(value) => (value * 1000.0) as i64,
            None => continue,
        };
        let frame_len = match parse_u64(parts[1]) {
            Some(value) => value,
            None => continue,
        };
        packets.push(PacketRow {
            ts_ms,
            frame_len,
            src_port: parse_u16(parts[6]),
            dst_port: parse_u16(parts[7]),
        });
    }
    Ok(pcap_metrics(&packets))
}

fn tshark_tls_fingerprint(
    pcap: &Path,
    tshark_bin: &str,
) -> Result<TlsFingerprint, Box<dyn std::error::Error>> {
    let mut command = ProcessCommand::new(tshark_bin);
    command.args([
        "-r",
        &pcap.display().to_string(),
        "-Y",
        "tls.handshake.type == 1",
        "-T",
        "fields",
        "-E",
        "header=n",
        "-E",
        "separator=\t",
        "-E",
        "occurrence=f",
    ]);
    for field in TSHARK_FINGERPRINT_FIELDS {
        command.args(["-e", field]);
    }
    let output = command.output()?;
    if !output.status.success() {
        return Err(format!("tshark failed: {}", String::from_utf8_lossy(&output.stderr)).into());
    }
    let stdout = String::from_utf8(output.stdout)?;
    for raw_line in stdout.lines() {
        let mut parts = raw_line.split('\t').collect::<Vec<_>>();
        parts.resize(TSHARK_FINGERPRINT_FIELDS.len(), "");
        if parts.iter().all(|part| part.trim().is_empty()) {
            continue;
        }
        return Ok(TlsFingerprint {
            client_hello_seen: true,
            ja3_hash: string_or_none(parts[1]),
            ja3_full: string_or_none(parts[2]),
            ja4_fingerprint: string_or_none(parts[3]),
            ja4_r: string_or_none(parts[4]),
            sni: string_or_none(parts[5]),
            alpn: string_or_none(parts[6]),
        });
    }
    Ok(TlsFingerprint::default())
}

fn pcap_metrics(packets: &[PacketRow]) -> PcapMetrics {
    let packet_count = packets.len() as u64;
    let byte_count = packets.iter().map(|packet| packet.frame_len).sum();
    let upload_packets = packets
        .iter()
        .filter(|packet| packet.dst_port == Some(443))
        .collect::<Vec<_>>();
    let download_packets = packets
        .iter()
        .filter(|packet| packet.src_port == Some(443))
        .collect::<Vec<_>>();
    let upload_bytes = upload_packets.iter().map(|packet| packet.frame_len).sum();
    let download_bytes = download_packets.iter().map(|packet| packet.frame_len).sum();
    let upload_download_ratio = if download_bytes > 0 {
        Some(upload_bytes as f64 / download_bytes as f64)
    } else {
        None
    };
    let sizes = packets
        .iter()
        .map(|packet| packet.frame_len)
        .collect::<Vec<_>>();
    let mut times = packets
        .iter()
        .map(|packet| packet.ts_ms)
        .collect::<Vec<_>>();
    times.sort_unstable();
    let inter_arrivals = times
        .windows(2)
        .filter_map(|window| u64::try_from(window[1].saturating_sub(window[0])).ok())
        .collect::<Vec<_>>();
    let session_duration_ms = match (times.first(), times.last()) {
        (Some(first), Some(last)) if last >= first => u64::try_from(last - first).ok(),
        _ => None,
    };
    PcapMetrics {
        packet_count,
        byte_count,
        upload_bytes,
        download_bytes,
        upload_download_ratio,
        packet_size_summary: series_summary(&sizes),
        inter_arrival_ms_summary: series_summary(&inter_arrivals),
        burst_count: inter_arrivals.iter().filter(|value| **value > 250).count() as u64,
        session_duration_ms,
        client_to_relay_packet_count: upload_packets.len() as u64,
        relay_to_client_packet_count: download_packets.len() as u64,
    }
}

fn metrics_json(metrics: Option<&PcapMetrics>) -> Value {
    let Some(metrics) = metrics else {
        return json!({});
    };
    let packet = summary_json(metrics.packet_size_summary.as_ref(), "packet_size");
    let inter = summary_json(
        metrics.inter_arrival_ms_summary.as_ref(),
        "inter_arrival_ms",
    );
    json!({
        "packet_count": metrics.packet_count,
        "byte_count": metrics.byte_count,
        "upload_bytes": metrics.upload_bytes,
        "download_bytes": metrics.download_bytes,
        "upload_download_ratio": metrics.upload_download_ratio,
        "packet_size_min": packet["packet_size_min"].clone(),
        "packet_size_max": packet["packet_size_max"].clone(),
        "packet_size_mean": packet["packet_size_mean"].clone(),
        "packet_size_p50": packet["packet_size_p50"].clone(),
        "packet_size_p90": packet["packet_size_p90"].clone(),
        "packet_size_p99": packet["packet_size_p99"].clone(),
        "inter_arrival_ms_min": inter["inter_arrival_ms_min"].clone(),
        "inter_arrival_ms_max": inter["inter_arrival_ms_max"].clone(),
        "inter_arrival_ms_mean": inter["inter_arrival_ms_mean"].clone(),
        "inter_arrival_ms_p50": inter["inter_arrival_ms_p50"].clone(),
        "inter_arrival_ms_p90": inter["inter_arrival_ms_p90"].clone(),
        "inter_arrival_ms_p99": inter["inter_arrival_ms_p99"].clone(),
        "burst_count": metrics.burst_count,
        "session_duration_ms": metrics.session_duration_ms,
        "client_to_relay_packet_count": metrics.client_to_relay_packet_count,
        "relay_to_client_packet_count": metrics.relay_to_client_packet_count,
    })
}

fn summary_json(summary: Option<&SeriesSummary>, prefix: &str) -> Value {
    let Some(summary) = summary else {
        return json!({
            format!("{prefix}_min"): Value::Null,
            format!("{prefix}_max"): Value::Null,
            format!("{prefix}_mean"): Value::Null,
            format!("{prefix}_p50"): Value::Null,
            format!("{prefix}_p90"): Value::Null,
            format!("{prefix}_p99"): Value::Null,
        });
    };
    json!({
        format!("{prefix}_min"): summary.min,
        format!("{prefix}_max"): summary.max,
        format!("{prefix}_mean"): summary.mean,
        format!("{prefix}_p50"): summary.p50,
        format!("{prefix}_p90"): summary.p90,
        format!("{prefix}_p99"): summary.p99,
    })
}

fn summary_value(values: &[u64]) -> Value {
    let Some(summary) = series_summary(values) else {
        return Value::Null;
    };
    json!({
        "min": summary.min,
        "max": summary.max,
        "mean": summary.mean,
        "p50": summary.p50,
        "p90": summary.p90,
        "p99": summary.p99,
    })
}

fn f64_summary_value(values: &[f64]) -> Value {
    if values.is_empty() {
        return Value::Null;
    }
    let mut sorted = values.to_vec();
    sorted.sort_by(|left, right| left.total_cmp(right));
    let sum = sorted.iter().sum::<f64>();
    let percentile = |pct: usize| -> f64 {
        let index = ((sorted.len().saturating_sub(1)) * pct) / 100;
        sorted[index]
    };
    json!({
        "min": sorted[0],
        "max": sorted[sorted.len() - 1],
        "mean": sum / sorted.len() as f64,
        "p50": percentile(50),
        "p90": percentile(90),
        "p99": percentile(99),
    })
}

fn series_summary(values: &[u64]) -> Option<SeriesSummary> {
    if values.is_empty() {
        return None;
    }
    let mut sorted = values.to_vec();
    sorted.sort_unstable();
    let sum: u64 = sorted.iter().sum();
    Some(SeriesSummary {
        min: sorted[0],
        max: sorted[sorted.len() - 1],
        mean: sum as f64 / sorted.len() as f64,
        p50: percentile(&sorted, 50),
        p90: percentile(&sorted, 90),
        p99: percentile(&sorted, 99),
    })
}

fn percentile(sorted: &[u64], percentile: usize) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    let index = ((sorted.len().saturating_sub(1)) * percentile) / 100;
    sorted[index]
}

/// Every reference fingerprint of the given kind: the top-level value plus one
/// per reference endpoint. Empty when the baseline carries none, which makes
/// the fingerprint comparison unavailable rather than a silent zero.
/// Is this reference endpoint a real browser, or just another controlled
/// non-browser client?
///
/// This distinction is the whole point of the fingerprint term. The existing
/// corpus is `curl_http2_origin_vps_ipv4_filtered` and
/// `controlled_python_websocket_origin_vps_ipv4_filtered` — curl and
/// python-websockets. Scoring "our JA4 matches the reference" against those
/// would reward looking like curl, which no censor confuses with a browser.
/// The goal is to be indistinguishable from a browser, so only a browser
/// baseline may supply the fingerprint to match.
///
/// Opt in explicitly with `"browser_baseline": true`, or implicitly via a
/// `client_type` that names a browser engine.
fn is_browser_baseline(entry: &Value) -> bool {
    if entry
        .get("browser_baseline")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        return true;
    }
    let client_type = entry
        .get("client_type")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_ascii_lowercase();
    ["chrome", "chromium", "firefox", "safari", "edge", "browser"]
        .iter()
        .any(|engine| client_type.contains(engine))
}

/// Every fingerprint of the given kind that comes from a BROWSER baseline.
/// Non-browser reference endpoints are deliberately skipped — see
/// [`is_browser_baseline`]. Empty means the fingerprint comparison cannot be
/// made, which must read as "not measured", never as a zero.
fn reference_fingerprints(reference: &Value, key: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    if is_browser_baseline(reference) {
        if let Some(value) = reference.get(key).and_then(Value::as_str) {
            out.push(value.to_string());
        }
    }
    for endpoint in reference
        .get("reference_endpoints")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        if !is_browser_baseline(endpoint) {
            continue;
        }
        if let Some(value) = endpoint.get(key).and_then(Value::as_str) {
            out.push(value.to_string());
        }
    }
    if key == "ja4_fingerprint" {
        // Drop anything that is not a canonical tshark JA4; comparing a
        // different JA4 dialect would manufacture a mismatch.
        out.retain(|value| is_canonical_ja4(value));
    }
    out.sort();
    out.dedup();
    out
}

/// Canonical JA4 shape, e.g. `t13d1516h2_8daaf6152771_e5627efa2ab1`.
///
/// This guard exists because the repo carries two different things both called
/// "JA4". `scripts/lib/ja4-clienthello-capture.py` emits its own
/// `JA4C`/`JA4E` pair (sorted cipher / extension SHA-256 prefixes, SNI
/// excluded) — that is what the chrome-like parity pin `d82cdc468f18` is. The
/// witness scorer, by contrast, reads tshark's `tls.handshake.ja4`, which is
/// the canonical string. Comparing one against the other always mismatches,
/// and the mismatch would look like a real mimicry failure rather than a unit
/// error. So a reference fingerprint that is not canonical JA4 is treated as
/// not comparable.
/// Which half of a canonical JA4 moved.
///
/// `t13d1516h2_8daaf6152771_806a8c22fdea` is head_cipherhash_exthash. The head
/// carries the SNI marker and the cipher/extension counts; the two hashes carry
/// the cipher and extension lists. A head-only difference means the same TLS
/// stack observed under different SNI conditions — not a different client.
enum Ja4MismatchPart {
    HeadOnly,
    Hashes,
}

fn ja4_mismatch_part(measured: Option<&str>, expected: Option<&str>) -> Ja4MismatchPart {
    let (Some(measured), Some(expected)) = (measured, expected) else {
        return Ja4MismatchPart::Hashes;
    };
    let tail = |value: &str| {
        value
            .split_once('_')
            .map(|(_, rest)| rest.to_ascii_lowercase())
    };
    match (tail(measured), tail(expected)) {
        (Some(a), Some(b)) if a == b => Ja4MismatchPart::HeadOnly,
        _ => Ja4MismatchPart::Hashes,
    }
}

fn is_canonical_ja4(value: &str) -> bool {
    let mut parts = value.split('_');
    let (Some(head), Some(cipher), Some(ext), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return false;
    };
    let hex12 = |s: &str| s.len() == 12 && s.bytes().all(|b| b.is_ascii_hexdigit());
    // head: protocol + version + sni marker + 2-digit cipher count + 2-digit
    // extension count + 2-char ALPN, e.g. `t13d1516h2`.
    head.len() == 10
        && head.as_bytes()[0].is_ascii_alphabetic()
        && head[1..3].bytes().all(|b| b.is_ascii_digit())
        && matches!(head.as_bytes()[3], b'd' | b'i')
        && head[4..8].bytes().all(|b| b.is_ascii_digit())
        && hex12(cipher)
        && hex12(ext)
}

/// How the reference corpus classifies for TLS-fingerprint purposes.
fn reference_tls_baseline_class(reference: Option<&Value>) -> &'static str {
    let Some(reference) = reference else {
        return "NONE";
    };
    if !reference_fingerprints(reference, "ja4_fingerprint").is_empty()
        || !reference_fingerprints(reference, "ja3_hash").is_empty()
    {
        return "BROWSER";
    }
    let has_any_fingerprint = reference.get("ja4_fingerprint").is_some()
        || reference.get("ja3_hash").is_some()
        || reference
            .get("reference_endpoints")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .any(|endpoint| {
                endpoint.get("ja4_fingerprint").is_some() || endpoint.get("ja3_hash").is_some()
            });
    if has_any_fingerprint {
        // Fingerprints exist, but they belong to curl / python / some other
        // non-browser client. Matching them is not the property we want.
        "NON_BROWSER_CONTROLLED_ENDPOINT"
    } else {
        "NONE"
    }
}

/// Similarity of two magnitudes on [0,1] by relative distance: identical -> 1.0,
/// an order of magnitude apart -> ~0.
fn magnitude_similarity(measured: f64, reference: f64) -> f64 {
    if !measured.is_finite() || !reference.is_finite() {
        return 0.0;
    }
    let scale = measured.abs().max(reference.abs()).max(1.0);
    (1.0 - ((measured - reference).abs() / scale)).clamp(0.0, 1.0)
}

/// Compare a measured distribution against the reference's, over the shape
/// percentiles both sides publish. `None` when the reference does not carry a
/// comparable distribution — the caller must then refuse to score, not guess.
fn distribution_similarity(measured: &SeriesSummary, reference: Option<&Value>) -> Option<f64> {
    let reference = reference?;
    let pick = |key: &str| reference.get(key).and_then(Value::as_f64);
    let pairs = [
        (measured.p50 as f64, pick("p50")),
        (measured.p90 as f64, pick("p90")),
        (measured.mean, pick("mean")),
    ];
    let scored: Vec<f64> = pairs
        .iter()
        .filter_map(|(m, r)| r.map(|r| magnitude_similarity(*m, r)))
        .collect();
    if scored.is_empty() {
        return None;
    }
    Some(scored.iter().sum::<f64>() / scored.len() as f64)
}

/// The real question this KPI is supposed to answer: does our traffic look like
/// the reference browser/client traffic?
///
/// It is deliberately computed ONLY from comparisons against the reference
/// profile, plus the classifier verdict. Presence of data proves nothing about
/// resemblance, so no "did we collect X" term appears here. Returns `None` when
/// there is no reference to compare against — in that case the KPI is not
/// measurable and must be reported as such rather than defaulted.
fn indistinguishability_components(
    classifier_clean: Option<bool>,
    pcap_metrics: Option<&PcapMetrics>,
    tls: &TlsFingerprint,
    reference: Option<&Value>,
) -> Option<(f64, Value)> {
    let reference = reference?;

    // TLS fingerprint MATCH against the reference — not "was it measured".
    // The baseline may publish a fingerprint at the top level, or one per
    // reference endpoint; a match against any reference endpoint counts.
    let ref_ja4 = reference_fingerprints(reference, "ja4_fingerprint");
    let ref_ja3 = reference_fingerprints(reference, "ja3_hash");
    let tls_match = match (tls.ja4_fingerprint.as_deref(), ref_ja4.is_empty()) {
        (Some(ours), false) => Some(bool_score(ref_ja4.iter().any(|theirs| theirs == ours))),
        _ => match (tls.ja3_hash.as_deref(), ref_ja3.is_empty()) {
            (Some(ours), false) => Some(bool_score(ref_ja3.iter().any(|theirs| theirs == ours))),
            _ => None,
        },
    };

    let timing_similarity = pcap_metrics
        .and_then(|m| m.inter_arrival_ms_summary.as_ref())
        .and_then(|s| distribution_similarity(s, reference.get("inter_arrival_distribution")));
    let size_similarity = pcap_metrics
        .and_then(|m| m.packet_size_summary.as_ref())
        .and_then(|s| distribution_similarity(s, reference.get("packet_size_distribution")));

    // Weighted over the comparisons we could actually make; a comparison that
    // could not be made is excluded rather than scored as zero or as one.
    let terms: Vec<(&str, f64, f64)> = [
        ("classifier_clean", classifier_clean.map(bool_score), 0.30),
        ("tls_fingerprint_match_vs_reference", tls_match, 0.35),
        ("timing_distribution_similarity", timing_similarity, 0.20),
        ("packet_size_distribution_similarity", size_similarity, 0.15),
    ]
    .into_iter()
    .filter_map(|(name, value, weight)| value.map(|value| (name, value, weight)))
    .collect();

    // The classifier term alone is not an indistinguishability measurement.
    if terms.len() < 2 {
        return None;
    }
    let weight_total: f64 = terms.iter().map(|(_, _, w)| *w).sum();
    let score = terms
        .iter()
        .map(|(_, value, weight)| value * weight)
        .sum::<f64>()
        / weight_total;

    let detail = terms
        .iter()
        .map(|(name, value, weight)| {
            (
                (*name).to_string(),
                json!({ "value": round3(*value), "weight": *weight }),
            )
        })
        .collect::<serde_json::Map<_, _>>();
    Some((round3(score), Value::Object(detail)))
}

/// Evidence-completeness components: "did we collect the inputs".
///
/// This used to be published as `witness_indistinguishability_score`, which it
/// never was: `timing_score` was 1.0 when timing data merely existed,
/// `size_distribution_score` was 1.0 whenever packets were not all the same
/// size (true of any traffic), `ratio_score` was 1.0 if any upload happened,
/// and `tls_fingerprint_score` was 1.0 when JA3/JA4 were *measured* rather than
/// *matching a browser*. Eighty percent of the weight was data collection, and
/// the only term that compared against a reference carried 0.05. A fully
/// collected capture of obviously-AEGIS traffic scored ~1.0.
fn component_scores(
    classifier_clean: bool,
    timing_present: bool,
    pcap_metrics: Option<&PcapMetrics>,
    ja3_status: &str,
    ja4_status: &str,
    runtime_clean: bool,
    reference_baseline_score: f64,
) -> Value {
    let ratio_score = pcap_metrics
        .and_then(|metrics| metrics.upload_download_ratio)
        .map(|ratio| if ratio > 0.0 { 1.0 } else { 0.0 })
        .unwrap_or(0.0);
    let size_distribution_score = pcap_metrics
        .and_then(|metrics| metrics.packet_size_summary.as_ref())
        .map(|summary| if summary.max > summary.min { 1.0 } else { 0.5 })
        .unwrap_or(0.0);
    json!({
        "classifier_score": bool_score(classifier_clean),
        "timing_score": bool_score(timing_present),
        "size_distribution_score": size_distribution_score,
        "ratio_score": ratio_score,
        "tls_fingerprint_score": match (ja3_status, ja4_status) {
            ("MEASURED", "MEASURED") => 1.0,
            ("MEASURED", _) => 0.5,
            _ => 0.0,
        },
        "runtime_linkage_score": bool_score(runtime_clean),
        "reference_baseline_score": reference_baseline_score,
    })
}

fn score_weights() -> Value {
    json!({
        "classifier_score": 0.20,
        "timing_score": 0.20,
        "size_distribution_score": 0.15,
        "ratio_score": 0.15,
        "tls_fingerprint_score": 0.15,
        "runtime_linkage_score": 0.10,
        "reference_baseline_score": 0.05,
    })
}

fn weighted_score(component_scores: &Value, weights: &Value) -> f64 {
    let mut score = 0.0;
    for (key, weight) in weights.as_object().into_iter().flatten() {
        score += component_scores
            .get(key)
            .and_then(Value::as_f64)
            .unwrap_or(0.0)
            * weight.as_f64().unwrap_or(0.0);
    }
    (score * 1000.0).round() / 1000.0
}

fn round3(value: f64) -> f64 {
    (value * 1000.0).round() / 1000.0
}

fn bool_score(value: bool) -> f64 {
    if value {
        1.0
    } else {
        0.0
    }
}

fn reference_status(reference_profile: Option<&Value>) -> String {
    let Some(reference) = reference_profile else {
        return "BLOCKED_REFERENCE_TIMING_MISSING".to_string();
    };
    reference
        .get("verdict")
        .and_then(Value::as_str)
        .or_else(|| reference.get("status").and_then(Value::as_str))
        .unwrap_or("PARTIAL")
        .to_string()
}

fn reference_verdict(reference: &Value) -> String {
    reference
        .get("verdict")
        .and_then(Value::as_str)
        .or_else(|| reference.get("status").and_then(Value::as_str))
        .unwrap_or("PARTIAL")
        .to_string()
}

fn reference_profiles(reference: &Value) -> Vec<String> {
    reference
        .get("profiles_covered")
        .or_else(|| reference.get("profiles"))
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(ToString::to_string)
        .collect()
}

fn aggregate_status(cells: &[Value], key: &str) -> &'static str {
    if cells
        .iter()
        .all(|cell| matches!(cell[key].as_str(), Some("PASS") | Some("MEASURED")))
    {
        if key == "ja3_status" || key == "ja4_status" {
            "MEASURED"
        } else {
            "PASS"
        }
    } else if cells
        .iter()
        .any(|cell| cell[key].as_str() == Some("NOT_MEASURED"))
    {
        "NOT_MEASURED"
    } else {
        "PARTIAL"
    }
}

fn aggregate_bool_status(cells: &[Value], key: &str) -> &'static str {
    if cells.iter().all(|cell| cell[key].as_bool() == Some(true)) {
        "PASS"
    } else if cells.iter().any(|cell| cell[key].as_bool() == Some(true)) {
        "PARTIAL"
    } else {
        "BLOCKED"
    }
}

fn canonical_transport(transport: &str) -> String {
    match transport {
        "https_ws" | "HttpsWs" | "https-ws" => "HttpsWs".to_string(),
        "grpc_stream" | "GrpcStream" | "grpc-stream" => "GrpcStream".to_string(),
        other => other.to_string(),
    }
}

fn selected_and_succeeded(events: &[Value], expected: &str) -> (bool, bool, Vec<String>) {
    let mut selected = false;
    let mut succeeded = false;
    let mut other_selected = Vec::new();
    for event in events {
        let code = event.get("event_code").and_then(Value::as_str);
        let fields = event.get("fields").unwrap_or(event);
        if code == Some("relay_transport_selected") {
            let transport = fields.get("transport").and_then(Value::as_str);
            if transport == Some(expected) {
                selected = true;
            } else if let Some(transport) = transport {
                other_selected.push(transport.to_string());
            }
        }
        if code == Some("relay_session_succeeded") {
            let transport = fields
                .get("chosen_transport")
                .or_else(|| fields.get("transport"))
                .and_then(Value::as_str);
            if transport == Some(expected) {
                succeeded = true;
            }
        }
    }
    other_selected.sort();
    other_selected.dedup();
    (selected, succeeded, other_selected)
}

fn number_from(value: &Value, keys: &[&str]) -> Option<u64> {
    keys.iter()
        .find_map(|key| value.get(*key).and_then(Value::as_u64))
}

fn parse_float(value: &str) -> Option<f64> {
    if value.trim().is_empty() {
        return None;
    }
    value.trim().parse::<f64>().ok()
}

fn parse_u64(value: &str) -> Option<u64> {
    if value.trim().is_empty() {
        return None;
    }
    value.trim().parse::<u64>().ok()
}

fn parse_u16(value: &str) -> Option<u16> {
    if value.trim().is_empty() {
        return None;
    }
    value.trim().parse::<u16>().ok()
}

fn string_or_none(value: &str) -> Option<String> {
    let value = value.trim();
    if value.is_empty() {
        None
    } else {
        Some(value.to_string())
    }
}

#[cfg(test)]
mod runtime_completion_tests {
    use super::*;

    fn runtime_score(events: &[Value]) -> Value {
        let empty = json!({});
        witness_score(WitnessScoreInput {
            transport: "grpc_stream",
            netem_profile: "runtime-only",
            pcap_path: Path::new("/nonexistent-a03-witness.pcap"),
            runtime_events: events,
            ndpi_summary: &empty,
            suricata_summary: &empty,
            reference_profile: None,
            tshark_bin: "unused-without-pcap",
        })
    }

    #[test]
    fn a03_neutral_completion_cannot_supply_runtime_success() {
        // `cancelled` is a defensive schema fixture, not a claim that the
        // current producer emits a completion event when its future is dropped.
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
                assert_eq!(score["runtime_transport_selected"], true);
                assert_eq!(score["relay_session_succeeded"], false);
                assert_eq!(score["runtime_linked"], false);
                assert_eq!(score["score_status"], "BLOCKED");
                assert!(score["blockers"]
                    .as_array()
                    .unwrap()
                    .contains(&json!("runtime_linkage_missing")));

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
                    .contains(&json!("runtime_linkage_missing")));
            }
        }
    }
}

#[cfg(test)]
mod indistinguishability_tests {
    use super::*;

    fn summary(p50: u64, p90: u64, mean: f64) -> SeriesSummary {
        SeriesSummary {
            min: p50,
            max: p90,
            mean,
            p50,
            p90,
            p99: p90,
        }
    }

    fn metrics(packet: SeriesSummary, inter_arrival: SeriesSummary) -> PcapMetrics {
        PcapMetrics {
            packet_count: 100,
            byte_count: 100_000,
            upload_bytes: 40_000,
            download_bytes: 60_000,
            upload_download_ratio: Some(0.666),
            packet_size_summary: Some(packet),
            inter_arrival_ms_summary: Some(inter_arrival),
            burst_count: 4,
            session_duration_ms: Some(5_000),
            client_to_relay_packet_count: 50,
            relay_to_client_packet_count: 50,
        }
    }

    fn reference(ja4: &str, packet_p50: u64, inter_arrival_p50: u64) -> Value {
        json!({
            "verdict": "SCOPED_REFERENCE_READY",
            "reference_endpoints": [{
                "name": "chrome-live-reference",
                // Browser-class on purpose: the fingerprint term only exists
                // when the reference is a browser.
                "client_type": "google_chrome_headless_new",
                "ja3_hash": "reference-ja3",
                "ja4_fingerprint": ja4,
            }],
            "packet_size_distribution": {
                "p50": packet_p50,
                "p90": packet_p50,
                "mean": packet_p50 as f64,
            },
            "inter_arrival_distribution": {
                "p50": inter_arrival_p50,
                "p90": inter_arrival_p50,
                "mean": inter_arrival_p50 as f64,
            },
        })
    }

    fn tls(ja4: &str) -> TlsFingerprint {
        TlsFingerprint {
            client_hello_seen: true,
            ja3_hash: Some("ours-ja3".to_string()),
            ja3_full: None,
            ja4_fingerprint: Some(ja4.to_string()),
            ja4_r: None,
            sni: Some("example.invalid".to_string()),
            alpn: Some("h2".to_string()),
        }
    }

    // REGRESSION: the published score was a weighted presence checklist —
    // 80% of the weight was "did we collect the data", and the only
    // reference-comparing term carried 0.05. A fully collected capture of
    // traffic that matched nothing scored ~0.975 and was reported as PASS.
    #[test]
    fn complete_but_obviously_distinguishable_capture_does_not_score_high() {
        let measured = metrics(summary(1400, 1400, 1400.0), summary(200, 200, 200.0));
        // Wrong fingerprint, packets an order of magnitude larger, pacing an
        // order of magnitude slower than the reference.
        let reference = reference("t13d1516h2_aaaaaaaaaaaa_bbbbbbbbbbbb", 120, 8);
        let (score, detail) = indistinguishability_components(
            Some(true),
            Some(&measured),
            &tls("t13d1011h1_cccccccccccc_dddddddddddd"),
            Some(&reference),
        )
        .expect("comparable terms exist");

        assert_eq!(detail["tls_fingerprint_match_vs_reference"]["value"], 0.0);
        assert!(
            score < FULL_PASS_THRESHOLD,
            "clearly distinguishable traffic must not clear the acceptance bar, got {score}"
        );
        // The old presence-weighted sum still scores it near 1.0 — kept as
        // proof that the two numbers are no longer the same quantity.
        let completeness = weighted_score(
            &component_scores(
                true,
                true,
                Some(&measured),
                "MEASURED",
                "MEASURED",
                true,
                1.0,
            ),
            &score_weights(),
        );
        assert!(
            completeness > 0.9,
            "completeness stays high: {completeness}"
        );
    }

    #[test]
    fn matching_fingerprint_and_shape_scores_high() {
        let measured = metrics(summary(1200, 1300, 1250.0), summary(10, 12, 11.0));
        let reference = reference("t13d1516h2_aaaaaaaaaaaa_bbbbbbbbbbbb", 1200, 10);
        let (score, _) = indistinguishability_components(
            Some(true),
            Some(&measured),
            &tls("t13d1516h2_aaaaaaaaaaaa_bbbbbbbbbbbb"),
            Some(&reference),
        )
        .expect("comparable terms exist");
        assert!(
            score >= FULL_PASS_THRESHOLD,
            "matching traffic should clear the bar, got {score}"
        );
    }

    // Without a reference there is nothing to be indistinguishable *from*.
    // Refusing to score is the only honest answer; the old code returned a
    // high number anyway.
    #[test]
    fn no_reference_means_no_score() {
        let measured = metrics(summary(1200, 1300, 1250.0), summary(10, 12, 11.0));
        assert!(
            indistinguishability_components(Some(true), Some(&measured), &tls("x"), None).is_none(),
            "no reference profile must yield no score"
        );
    }

    // REGRESSION: a capture nobody ran nDPI/Suricata over used to score the
    // 0.30-weight classifier term at zero, which reads as "the classifier
    // flagged us" rather than "no classifier ran". That is a false negative,
    // and it would have made the first real witness measurement look worse
    // than the traffic was.
    #[test]
    fn an_unrun_classifier_drops_out_instead_of_scoring_zero() {
        let measured = metrics(summary(1200, 1300, 1250.0), summary(10, 12, 11.0));
        let reference = reference("t13d1516h2_aaaaaaaaaaaa_bbbbbbbbbbbb", 1200, 10);
        let matching = tls("t13d1516h2_aaaaaaaaaaaa_bbbbbbbbbbbb");

        let (with_classifier, detail_yes) = indistinguishability_components(
            Some(true),
            Some(&measured),
            &matching,
            Some(&reference),
        )
        .expect("scored");
        let (without_classifier, detail_no) =
            indistinguishability_components(None, Some(&measured), &matching, Some(&reference))
                .expect("still scorable from the remaining terms");

        assert!(detail_yes.get("classifier_clean").is_some());
        assert!(
            detail_no.get("classifier_clean").is_none(),
            "an un-run classifier must not appear as a scored term"
        );
        // The un-run case reweights over the remaining terms, so it lands near
        // the measured-clean score rather than being dragged toward zero.
        let (dirty, _) = indistinguishability_components(
            Some(false),
            Some(&measured),
            &matching,
            Some(&reference),
        )
        .expect("scored");
        assert!(
            (with_classifier - without_classifier).abs() < 0.05,
            "an un-run term should reweight, not swing the score: {with_classifier} vs {without_classifier}"
        );
        assert!(
            without_classifier - dirty > 0.25,
            "scoring an un-run classifier as an alert is the false negative this guards: \
             not-measured {without_classifier} vs measured-dirty {dirty}"
        );
        // And a classifier that really did flag the traffic must still hurt.
        assert!(dirty < with_classifier);
    }

    #[test]
    fn classifier_alone_is_not_an_indistinguishability_measurement() {
        // Reference carries no fingerprints and no distributions: only the
        // classifier term survives, which is not a resemblance measurement.
        let bare = json!({ "verdict": "SCOPED_REFERENCE_READY" });
        assert!(indistinguishability_components(
            Some(true),
            None,
            &TlsFingerprint::default(),
            Some(&bare)
        )
        .is_none());
    }

    #[test]
    fn reference_fingerprints_are_read_from_endpoints_and_top_level() {
        let value = json!({
            "browser_baseline": true,
            "ja4_fingerprint": "t13d1516h2_cccccccccccc_cccccccccccc",
            "reference_endpoints": [
                {
                    "client_type": "chrome_headless",
                    "ja4_fingerprint": "t13d1516h2_aaaaaaaaaaaa_aaaaaaaaaaaa",
                },
                {
                    "browser_baseline": true,
                    "ja4_fingerprint": "t13d1516h2_bbbbbbbbbbbb_bbbbbbbbbbbb",
                },
                { "client_type": "chrome_headless", "name": "no-fingerprint" },
            ],
        });
        assert_eq!(
            reference_fingerprints(&value, "ja4_fingerprint"),
            vec![
                "t13d1516h2_aaaaaaaaaaaa_aaaaaaaaaaaa",
                "t13d1516h2_bbbbbbbbbbbb_bbbbbbbbbbbb",
                "t13d1516h2_cccccccccccc_cccccccccccc",
            ]
        );
        assert!(reference_fingerprints(&value, "ja3_hash").is_empty());
    }

    // REGRESSION: the shipped reference corpus is curl and python-websockets.
    // Scoring "our JA4 matches the reference" against those rewards looking
    // like curl, which is not the property the KPI names. A non-browser
    // reference must yield no fingerprint to match.
    #[test]
    fn reference_without_a_missing_pcap_reports_fingerprint_comparison() {
        // The comparison is what turns "we measured a fingerprint" into "this
        // capture is the browser it claims to be". Before this, an
        // unconditional `ja3_ja4_measured_but_not_compared` blocker held every
        // reference at PARTIAL forever, and with it every matrix cell using one.
        let missing = std::path::Path::new("/nonexistent-reference.pcap");
        let empty = json!({});
        let build = |ja4: Option<&str>| {
            reference_pcap_score(ReferencePcapInput {
                artifact: "t",
                transport: "https_ws",
                netem_profile: "clean_fiber",
                client_type: "chrome",
                endpoint_url: "https://example.invalid/",
                provider: "cloudflare_fronted_path",
                pcap_path: missing,
                ndpi_summary: &empty,
                suricata_summary: &empty,
                tshark_bin: "tshark",
                expected_ja3: None,
                expected_ja4: ja4,
            })
        };

        // A missing pcap still blocks, and the expected value is echoed back so
        // a reader can see what the profile was checked against.
        let with_expectation = build(Some("t13d1516h2_8daaf6152771_806a8c22fdea"));
        assert_eq!(
            with_expectation["verdict"], "BLOCKED_REFERENCE_PCAP_MISSING",
            "a missing pcap must block regardless of what was expected"
        );
        assert_eq!(
            with_expectation["expected_ja4"],
            "t13d1516h2_8daaf6152771_806a8c22fdea"
        );
        // Nothing was measured, so there is nothing to compare — null, not false.
        assert!(with_expectation["ja4_matches_expected"].is_null());

        // And the permanent TODO blocker is gone in both directions.
        for profile in [build(None), with_expectation] {
            let blockers: Vec<&str> = profile["blockers"]
                .as_array()
                .unwrap()
                .iter()
                .filter_map(Value::as_str)
                .collect();
            assert!(
                !blockers.contains(&"ja3_ja4_measured_but_not_compared"),
                "the unconditional not-compared blocker must not come back: {blockers:?}"
            );
        }
    }

    #[test]
    fn non_browser_reference_supplies_no_fingerprint() {
        let curl_and_python = json!({
            "reference_endpoints": [
                {
                    "name": "websocket_reference",
                    "client_type": "controlled_python_websocket_origin_vps_ipv4_filtered",
                    "ja3_hash": "3adacb99ecb51ed59c4f6c4ed9a7dcaa",
                    "ja4_fingerprint": "t13d3112h1_e8f1e7e78f70_d41ae481755e",
                },
                {
                    "name": "grpc_reference",
                    "client_type": "curl_http2_origin_vps_ipv4_filtered",
                    "ja3_hash": "0149f47eabf9a20d0893e2a44e5a6323",
                    "ja4_fingerprint": "t13d3112h2_e8f1e7e78f70_b26ce05bbdd6",
                },
            ],
        });
        assert!(reference_fingerprints(&curl_and_python, "ja4_fingerprint").is_empty());
        assert!(reference_fingerprints(&curl_and_python, "ja3_hash").is_empty());
        assert_eq!(
            reference_tls_baseline_class(Some(&curl_and_python)),
            "NON_BROWSER_CONTROLLED_ENDPOINT",
            "curl and python must not be reported as a browser baseline"
        );

        // And the fingerprint term must drop out rather than score zero: a
        // mismatch against curl is not evidence either way.
        let measured = metrics(summary(1200, 1300, 1250.0), summary(10, 12, 11.0));
        let mut with_shapes = curl_and_python.clone();
        with_shapes["packet_size_distribution"] = json!({"p50": 1200, "p90": 1300, "mean": 1250.0});
        with_shapes["inter_arrival_distribution"] = json!({"p50": 10, "p90": 12, "mean": 11.0});
        let (_, detail) = indistinguishability_components(
            Some(true),
            Some(&measured),
            &tls("ours"),
            Some(&with_shapes),
        )
        .expect("shape terms are still comparable");
        assert!(
            detail.get("tls_fingerprint_match_vs_reference").is_none(),
            "no browser baseline means no fingerprint term, not a zero"
        );
    }

    // The repo has two things called JA4: the parity harness emits its own
    // sorted-cipher/extension pair (d82cdc468f18), tshark emits the canonical
    // string. Comparing across dialects manufactures a mismatch that reads as
    // a mimicry failure.
    #[test]
    fn non_canonical_ja4_is_not_comparable() {
        assert!(is_canonical_ja4("t13d1516h2_8daaf6152771_e5627efa2ab1"));
        assert!(is_canonical_ja4("t13d1011h1_61a7ad8aa9b6_3fcd1a44f3e3"));
        assert!(!is_canonical_ja4("d82cdc468f18"));
        assert!(!is_canonical_ja4("d82cdc468f18_a87e1bc790af"));
        assert!(!is_canonical_ja4(""));

        let harness_dialect = json!({
            "reference_endpoints": [{
                "client_type": "google_chrome_headless_new",
                // The parity harness's JA4C, not a canonical JA4.
                "ja4_fingerprint": "d82cdc468f18",
            }],
        });
        assert!(
            reference_fingerprints(&harness_dialect, "ja4_fingerprint").is_empty(),
            "a non-canonical JA4 must not be compared against a tshark JA4"
        );
    }

    #[test]
    fn browser_reference_is_recognised_by_client_type() {
        let chrome = json!({
            "reference_endpoints": [{
                "name": "chrome_live",
                "client_type": "google_chrome_headless_new",
                "ja4_fingerprint": "t13d1516h2_8daaf6152771_e5627efa2ab1",
            }],
        });
        assert_eq!(reference_tls_baseline_class(Some(&chrome)), "BROWSER");
        assert_eq!(
            reference_fingerprints(&chrome, "ja4_fingerprint"),
            vec!["t13d1516h2_8daaf6152771_e5627efa2ab1"]
        );
    }
}
