//! Consistency checks on declared provenance, never proof of capture contents
//! or statistical independence. Pair keys identify the same experimental trial;
//! actual sessions and captures can differ between policies.
use super::Input;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

const MAX_TRAINING_UNITS: usize = 100_000;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Unit {
    session_id: String,
    trial_id: String,
    network_id: String,
    time_holdout_id: String,
    capture_sha256: String,
    capture_started_unix_ms: u64,
    capture_finished_unix_ms: u64,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct StudyProvenance {
    schema_version: u8,
    frozen_bins_sha256: String,
    bins_frozen_unix_ms: u64,
    training_units: Vec<Unit>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PolicyProvenance {
    source_sha256: String,
    /// Exactly one metadata row for each sample, in the same order.
    sample_units: Vec<Unit>,
}

fn identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
}

fn digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn hash<T: Serialize>(value: &T) -> Result<String, String> {
    let bytes = serde_json::to_vec(value).map_err(|_| "provenance encoding failed")?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

#[derive(PartialEq, Eq)]
struct CaptureDeclaration<'a> {
    network: &'a str,
    started: u64,
    finished: u64,
}

fn record_capture<'a>(
    declarations: &mut BTreeMap<&'a str, CaptureDeclaration<'a>>,
    unit: &'a Unit,
) -> Result<(), String> {
    let declaration = CaptureDeclaration {
        network: &unit.network_id,
        started: unit.capture_started_unix_ms,
        finished: unit.capture_finished_unix_ms,
    };
    if let Some(prior) = declarations.get(unit.capture_sha256.as_str()) {
        if prior != &declaration {
            return Err("conflicting capture declarations for one SHA-256".into());
        }
    } else {
        declarations.insert(unit.capture_sha256.as_str(), declaration);
    }
    Ok(())
}

impl Unit {
    fn validate(&self) -> Result<(), String> {
        if [
            &self.session_id,
            &self.trial_id,
            &self.network_id,
            &self.time_holdout_id,
        ]
        .iter()
        .any(|id| !identifier(id))
            || !digest(&self.capture_sha256)
            || self.capture_started_unix_ms == 0
            || self.capture_finished_unix_ms < self.capture_started_unix_ms
        {
            return Err("invalid bounded provenance unit or capture interval".into());
        }
        Ok(())
    }

    fn pair_key(&self) -> (&str, &str, &str) {
        (&self.trial_id, &self.network_id, &self.time_holdout_id)
    }
}

pub(super) fn report(input: &Input) -> Result<Value, String> {
    let Some(study) = &input.provenance else {
        if input.policies.iter().any(|p| p.provenance.is_some()) {
            return Err(
                "policy provenance requires shared training and frozen-bin provenance".into(),
            );
        }
        return Ok(json!({
            "status":"unverified_legacy_input", "paired_units_checked":false,
            "training_separation_checked":false, "capture_contents_verified":false,
            "frozen_bin_contents_verified":false, "statistical_independence_proven":false
        }));
    };
    if study.schema_version != 1
        || !digest(&study.frozen_bins_sha256)
        || study.bins_frozen_unix_ms == 0
        || study.training_units.is_empty()
        || study.training_units.len() > MAX_TRAINING_UNITS
    {
        return Err(
            "expected provenance v1, frozen-bin SHA-256 and 1..=100000 training units".into(),
        );
    }

    let mut training_pairs = BTreeSet::new();
    let mut capture_declarations = BTreeMap::new();
    let mut training_sessions = BTreeSet::new();
    let mut training_trials = BTreeSet::new();
    let mut training_captures = BTreeSet::new();
    let mut training_holdouts = BTreeSet::new();
    for unit in &study.training_units {
        unit.validate()?;
        record_capture(&mut capture_declarations, unit)?;
        if unit.capture_finished_unix_ms > study.bins_frozen_unix_ms {
            return Err("training captures must finish before the declared bin freeze".into());
        }
        if !training_pairs.insert(unit.pair_key()) {
            return Err("duplicate training trial/network/time-holdout unit".into());
        }
        training_sessions.insert(unit.session_id.as_str());
        training_trials.insert(unit.trial_id.as_str());
        training_captures.insert(unit.capture_sha256.as_str());
        training_holdouts.insert(unit.time_holdout_id.as_str());
    }

    let mut reference_population = None;
    let mut policy_bindings = Vec::with_capacity(input.policies.len());
    let mut prior_policy_sessions = BTreeSet::new();
    let mut prior_policy_captures = BTreeSet::new();
    for policy in &input.policies {
        let metadata = policy
            .provenance
            .as_ref()
            .ok_or("shared provenance requires metadata for every policy")?;
        if !digest(&metadata.source_sha256) || metadata.sample_units.len() != policy.samples.len() {
            return Err(
                "policy source SHA-256 and one provenance unit per sample are required".into(),
            );
        }
        let mut population = BTreeMap::new();
        let mut sessions = BTreeSet::new();
        let mut captures = BTreeSet::new();
        for (sample, unit) in policy.samples.iter().zip(&metadata.sample_units) {
            unit.validate()?;
            if unit.capture_started_unix_ms <= study.bins_frozen_unix_ms {
                return Err("evaluation captures must start after the declared bin freeze".into());
            }
            if training_sessions.contains(unit.session_id.as_str())
                || training_trials.contains(unit.trial_id.as_str())
                || training_captures.contains(unit.capture_sha256.as_str())
                || training_holdouts.contains(unit.time_holdout_id.as_str())
            {
                return Err(
                    "evaluation reuses a training session, trial, capture or time holdout".into(),
                );
            }
            // This schema covers separately captured policy trials. Reusing a
            // capture for offline transformations needs another measurement model.
            if prior_policy_sessions.contains(unit.session_id.as_str())
                || prior_policy_captures.contains(unit.capture_sha256.as_str())
            {
                return Err(
                    "paired policies must use distinct capture and session identifiers".into(),
                );
            }
            record_capture(&mut capture_declarations, unit)?;
            if population.insert(unit.pair_key(), sample.label).is_some() {
                return Err("duplicate evaluation trial/network/time-holdout unit".into());
            }
            sessions.insert(unit.session_id.as_str());
            captures.insert(unit.capture_sha256.as_str());
        }
        if reference_population
            .as_ref()
            .is_some_and(|reference| reference != &population)
        {
            return Err("frontier policies must use the same paired trial/network/time-holdout units and labels".into());
        }
        // One capture/session can contain several trial samples in one policy;
        // no statistical independence is inferred from that grouping.
        prior_policy_sessions.extend(sessions.iter().copied());
        prior_policy_captures.extend(captures.iter().copied());
        // Arrays, rather than JSON object keys, make tuple encoding explicit
        // and canonical. Sorting is supplied by BTreeMap; row order is irrelevant.
        let population_rows = population
            .iter()
            .map(|((trial, network, holdout), label)| (trial, network, holdout, label))
            .collect::<Vec<_>>();
        policy_bindings.push(json!({
            "name":policy.name, "source_sha256":metadata.source_sha256,
            "sample_unit_manifest_sha256":hash(metadata)?,
            "paired_population_sha256":hash(&population_rows)?,
            "evaluation_units":population.len(), "sessions":sessions.len(),
            "capture_sha256":captures
        }));
        reference_population = Some(population);
    }
    Ok(json!({
        "status":"declared_paired_units_consistent", "schema_version":1,
        "paired_units_checked":true, "training_separation_checked":true,
        "distinct_policy_captures_and_sessions_checked":true,
        "capture_declarations_consistency_checked":true,
        "declared_freeze_chronology_checked":true,
        "frozen_bins_sha256":study.frozen_bins_sha256,
        "bins_frozen_unix_ms":study.bins_frozen_unix_ms,
        "training_units":study.training_units.len(),
        "training_manifest_sha256":hash(study)?, "policies":policy_bindings,
        "capture_contents_verified":false, "frozen_bin_contents_verified":false,
        "statistical_independence_proven":false
    }))
}

#[cfg(test)]
#[path = "provenance_tests.rs"]
mod tests;
