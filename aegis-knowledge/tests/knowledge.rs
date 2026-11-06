use aegis_knowledge::{Knowledge, StrategyDescriptor};

#[test]
fn embedded_knowledge_loads_and_verifies_manifest() {
    let knowledge = Knowledge::load_embedded().expect("embedded knowledge loads");

    assert_eq!(knowledge.manifest.version, "seed");
    assert!(knowledge.browser_corpus.fingerprints.len() >= 4);
    for target_class in ["legacy_tls", "https_ws", "masque_derived"] {
        assert!(
            knowledge
                .browser_corpus
                .fingerprints
                .iter()
                .any(|fingerprint| fingerprint.target_class == target_class),
            "missing primary target class {target_class}"
        );
    }
    assert!(knowledge.manifest.file("ja3-browser-corpus.json").is_some());
    knowledge
        .verify_integrity()
        .expect("manifest hashes verify");
}

#[test]
fn priors_differ_by_transport_and_region() {
    let knowledge = Knowledge::load_embedded().expect("embedded knowledge loads");

    let cn_legacy = knowledge.priors_for(
        &StrategyDescriptor::new("legacy_tls")
            .with_region("cn")
            .with_alpn(["http/1.1"]),
    );
    let cn_ws = knowledge.priors_for(
        &StrategyDescriptor::new("https_ws")
            .with_region("cn")
            .with_alpn(["h2", "http/1.1"]),
    );
    let unknown_legacy =
        knowledge.priors_for(&StrategyDescriptor::new("legacy_tls").with_region("unknown"));

    assert!(cn_ws.score > cn_legacy.score);
    assert!(unknown_legacy.score > cn_legacy.score);
    assert!(!cn_legacy.reasons.is_empty());
}

#[test]
fn exact_ja3_match_increases_confidence() {
    let knowledge = Knowledge::load_embedded().expect("embedded knowledge loads");

    let matched = knowledge
        .priors_for(&StrategyDescriptor::new("https_ws").with_ja3_hash("placeholder-chrome-ja3"));

    assert!(matched.confidence >= 0.7);
    assert!(matched
        .reasons
        .iter()
        .any(|reason| reason == "exact-ja3-corpus-match"));
}
