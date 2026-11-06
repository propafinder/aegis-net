//! Called only after the existing paired/frozen provenance consistency gate.
use super::Input;
use aegis_core::traffic_privacy::binary_hypothesis::diagnose;
use serde_json::{json, Value};

pub(super) fn report(input: &Input) -> Result<Value, String> {
    if input.provenance.is_none() {
        return Ok(
            json!({"status":"unknown_unverified_provenance", "policies":[],
            "population_distance_established":false, "whole_flow_privacy_guarantee":false,
            "awgn_or_square_root_guarantee":false}),
        );
    }
    if input.alphabet.labels != 2 {
        return Ok(
            json!({"status":"unknown_nonbinary_label_alphabet", "policies":[],
            "population_distance_established":false, "whole_flow_privacy_guarantee":false,
            "awgn_or_square_root_guarantee":false}),
        );
    }
    // Provenance fields remain private to their validator. The enclosing report
    // supplies the validated declared freeze/hash and population bindings.
    let mut policies = Vec::with_capacity(input.policies.len());
    for policy in &input.policies {
        let diagnostic = diagnose(&policy.samples, &input.alphabet).map_err(str::to_owned)?;
        policies.push(json!({"name":policy.name, "diagnostic":diagnostic}));
    }
    Ok(
        json!({"status":"declared_provenance_checked_empirical_only", "policies":policies,
        "scope":"conditional feature histograms for labels 0/1; no sequence, capture-content or population proof",
        "frozen_bin_contents_verified":false, "source_feature_extraction_verified":false,
        "capture_contents_verified":false, "statistical_independence_proven":false,
        "population_distance_established":false, "whole_flow_privacy_guarantee":false,
        "awgn_or_square_root_guarantee":false, "automatic_policy_adoption":false}),
    )
}

#[cfg(test)]
#[path = "binary_tests.rs"]
mod tests;
