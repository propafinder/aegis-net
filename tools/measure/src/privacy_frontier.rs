//! Bounded measurements only; this command does not infer a formal privacy bound.
use aegis_core::traffic_privacy::leakage::{
    empirical_frontier, estimate, select_measured_policy, Alphabet, LeakageSample,
};
use serde::Deserialize;
use serde_json::{json, Value};

mod binary;
mod provenance;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Policy {
    name: String,
    samples: Vec<LeakageSample>,
    #[serde(default)]
    provenance: Option<provenance::PolicyProvenance>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Qos {
    max_added_bytes: f64,
    max_added_delay_ms: f64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    alphabet: Alphabet,
    assume_iid_fixed_alphabet: bool,
    delta: f64,
    policies: Vec<Policy>,
    #[serde(default)]
    qos: Option<Qos>,
    #[serde(default)]
    provenance: Option<provenance::StudyProvenance>,
}

pub fn privacy_frontier_report(input: &Value) -> Result<Value, String> {
    let input: Input =
        serde_json::from_value(input.clone()).map_err(|_| "invalid privacy frontier schema")?;
    if input.policies.is_empty() || input.policies.len() > 64 {
        return Err("expected 1..=64 policies".into());
    }
    let mut estimates = Vec::new();
    let mut names = std::collections::BTreeSet::new();
    let mut total_samples = 0_usize;
    let mut reference_label_counts = None;
    for policy in &input.policies {
        if policy.name.is_empty()
            || policy.name.len() > 64
            || !policy
                .name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
            || !names.insert(policy.name.clone())
        {
            return Err("policy names must be unique bounded nonsecret identifiers".into());
        }
        total_samples = total_samples
            .checked_add(policy.samples.len())
            .ok_or("sample budget overflow")?;
        if total_samples > 1_000_000 {
            return Err("combined sample budget exceeded".into());
        }
        estimates.push(estimate(
            &policy.samples,
            &input.alphabet,
            input.assume_iid_fixed_alphabet,
            input.delta,
        )?);
        let mut label_counts = vec![0_usize; input.alphabet.labels];
        for sample in &policy.samples {
            label_counts[sample.label] += 1;
        }
        if reference_label_counts
            .as_ref()
            .is_some_and(|reference| reference != &label_counts)
        {
            return Err("frontier policies must use the same evaluation label counts".into());
        }
        reference_label_counts = Some(label_counts);
    }
    let provenance = provenance::report(&input)?;
    let binary = binary::report(&input)?;
    let frontier = empirical_frontier(&estimates);
    let selected = input
        .qos
        .as_ref()
        .map(|q| select_measured_policy(&estimates, q.max_added_bytes, q.max_added_delay_ms))
        .transpose()?
        .flatten();
    Ok(
        json!({ "artifact_schema": "aegis_empirical_privacy_frontier_v1",
        "scope": "nondominated measured fixed-alphabet points; no theoretical rate-distortion or flow privacy guarantee",
        "assume_iid_fixed_alphabet":input.assume_iid_fixed_alphabet,
        "intervals_are_per_policy_not_simultaneous":true,
        "provenance_validation":provenance,
        "binary_hypothesis_diagnostics":binary,
        "automatic_policy_adoption":false,
        "formal_dp_accounting":false,"theoretical_rate_distortion_bound":false,
        "policies": input.policies.iter().zip(estimates).map(|(p,e)| json!({"name":p.name,"estimate":e})).collect::<Vec<_>>(),
        "empirical_nondominated_policy_indices":frontier,
        "qos_selected_measured_policy_index":selected,
        "installed_acceptance":false,"target_network_acceptance":false,"beta_exit":false }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parses_real_input_and_refuses_unsupported_guarantees() {
        let input = json!({"alphabet":{"labels":2,"features":2},"assume_iid_fixed_alphabet":false,"delta":0.05,
            "policies":[{"name":"measured","samples":[{"label":0,"feature":0,"added_bytes":32,"added_delay_ms":2.0}]}]});
        let result = privacy_frontier_report(&input).unwrap();
        assert_eq!(result["formal_dp_accounting"], false);
        assert_eq!(
            result["provenance_validation"]["status"],
            "unverified_legacy_input"
        );
        assert_eq!(result["automatic_policy_adoption"], false);
        assert_eq!(
            result["policies"][0]["estimate"]["iid_confidence_interval_bits"],
            Value::Null
        );
        let mut bad = input;
        bad["epsilon"] = json!(1.0);
        assert!(privacy_frontier_report(&bad).is_err());
    }

    #[test]
    fn qos_selection_uses_comparable_measured_labels_and_refuses_unmatched_populations() {
        let mut input = json!({"alphabet":{"labels":2,"features":2},"assume_iid_fixed_alphabet":false,"delta":0.05,
            "qos":{"max_added_bytes":160,"max_added_delay_ms":4},"policies":[
                {"name":"baseline","samples":[
                    {"label":0,"feature":0,"added_bytes":0,"added_delay_ms":0},
                    {"label":1,"feature":1,"added_bytes":0,"added_delay_ms":0}]},
                {"name":"cover","samples":[
                    {"label":0,"feature":0,"added_bytes":128,"added_delay_ms":2},
                    {"label":1,"feature":0,"added_bytes":128,"added_delay_ms":2}]}]});
        let report = privacy_frontier_report(&input).unwrap();
        assert_eq!(report["qos_selected_measured_policy_index"], 1);
        assert_eq!(
            report["policies"][0]["estimate"]["empirical_mutual_information_bits"],
            1.0
        );
        assert_eq!(
            report["policies"][1]["estimate"]["empirical_mutual_information_bits"],
            0.0
        );
        input["qos"]["max_added_bytes"] = json!(64);
        assert_eq!(
            privacy_frontier_report(&input).unwrap()["qos_selected_measured_policy_index"],
            0
        );
        input["policies"][1]["samples"][1]["label"] = json!(0);
        assert!(privacy_frontier_report(&input).is_err());
    }
}
