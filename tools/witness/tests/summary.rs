use aegis_witness::{
    classify_tls::TlsWitnessClassification,
    report::WitnessEvent,
    score::WitnessScore,
    summary::{summarize_events, WitnessSummary},
};

fn event(label: &str, combined: f32, is_tls: bool) -> WitnessEvent {
    WitnessEvent::new(
        label.to_string(),
        None,
        TlsWitnessClassification {
            is_tls_client_hello: is_tls,
            legacy_version: is_tls.then_some(0x0303),
            cipher_suites: Vec::new(),
            extension_types: Vec::new(),
            supported_groups: Vec::new(),
            sni: None,
            alpn: Vec::new(),
            ja3: None,
            ja3_md5: None,
        },
        WitnessScore {
            ja3_present: combined,
            alpn_match: combined,
            sni_structure: combined,
            extension_structure: combined,
            combined,
        },
    )
}

#[test]
fn summarizes_events_by_label() {
    let summary = summarize_events(&[
        event("legacy_tls", 1.0, true),
        event("legacy_tls", 0.5, true),
        event("https_ws", 0.0, false),
    ]);

    assert_eq!(summary.groups.len(), 2);
    assert_eq!(summary.groups[0].label, "https_ws");
    assert_eq!(summary.groups[0].total_records, 1);
    assert_eq!(summary.groups[0].tls_client_hello_records, 0);
    assert_eq!(summary.groups[1].label, "legacy_tls");
    assert_eq!(summary.groups[1].total_records, 2);
    assert_eq!(summary.groups[1].tls_client_hello_records, 2);
    assert_eq!(summary.groups[1].combined_avg, 0.75);
}

#[test]
fn renders_markdown_score_table() {
    let summary: WitnessSummary = summarize_events(&[event("legacy|tls", 1.0, true)]);
    let table = summary.to_markdown_table();

    assert!(table.contains("| Label | Records | TLS ClientHello | JA3 |"));
    assert!(table.contains("legacy\\|tls"));
    assert!(table.contains("| 1.000 |"));
}
