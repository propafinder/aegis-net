//! Private content-bound assembler; export/capture and cost origins stay unknown.
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
};

mod frozen_bins;
mod packet_rows;
use frozen_bins::FrozenBins;
use packet_rows::{Flow, Selection};
pub(crate) const PACKET_ROWS_V1_HEADER: &str = packet_rows::HEADER;

const MAX_MANIFEST: u64 = 1024 * 1024;
const MAX_SIDECAR: u64 = 64 * 1024;
const MAX_EXPORT: u64 = 4 * 1024 * 1024;
const MAX_TOTAL_EXPORT: usize = 64 * 1024 * 1024;
const MAX_ROWS: usize = 262_144;
const MAX_TRIALS: usize = 1024;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct FileRef {
    path: PathBuf,
    sha256: String,
}
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum SourceKind {
    SyntheticFixture,
    DeclaredRetainedExport,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    schema_version: u8,
    source_kind: SourceKind,
    bins: FileRef,
    training_units: Vec<Unit>,
    policies: Vec<Policy>,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Unit {
    session_id: String,
    trial_id: String,
    network_id: String,
    time_holdout_id: String,
    capture_sha256: String,
    capture_started_unix_ms: u64,
    capture_finished_unix_ms: u64,
}
impl Unit {
    fn key(&self) -> (&str, &str, &str) {
        (&self.trial_id, &self.network_id, &self.time_holdout_id)
    }
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Policy {
    name: String,
    exports: Vec<Export>,
    costs: FileRef,
    trials: Vec<Trial>,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Export {
    id: String,
    file: FileRef,
    capture_sha256: String,
    network_id: String,
    capture_started_unix_ms: u64,
    capture_finished_unix_ms: u64,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Trial {
    unit: Unit,
    label: u8,
    export_id: String,
    flow: Flow,
    window_started_unix_us: u64,
    window_finished_unix_us: u64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Costs {
    schema_version: u8,
    rows: Vec<Cost>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Cost {
    trial_id: String,
    network_id: String,
    time_holdout_id: String,
    added_bytes: u64,
    added_delay_ms: f64,
}

fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn json_digest<T: Serialize>(value: &T) -> Result<String, &'static str> {
    serde_json::to_vec(value)
        .map(|bytes| digest(&bytes))
        .map_err(|_| "study binding encoding failed")
}
fn identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
}
fn hash_string(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn read_private(path: &Path, limit: u64) -> Result<Vec<u8>, &'static str> {
    if !path.is_absolute() || path.as_os_str().len() > 4096 {
        return Err("study input needs a bounded absolute private path");
    }
    aegis_core::secret_file::trusted_parent(path)
        .map_err(|_| "study input ancestry is not private")?;
    aegis_core::secret_file::read(path, limit)
        .map(|bytes| bytes.to_vec())
        .map_err(|_| "study input must be a bounded descriptor-checked private file")
}
fn read_bound(reference: &FileRef, limit: u64) -> Result<Vec<u8>, &'static str> {
    if !hash_string(&reference.sha256) {
        return Err("invalid input SHA-256 declaration");
    }
    let bytes = read_private(&reference.path, limit)?;
    if digest(&bytes) != reference.sha256 {
        return Err("study input content SHA-256 mismatch");
    }
    Ok(bytes)
}
fn decode<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T, &'static str> {
    serde_json::from_slice(bytes).map_err(|_| "invalid strict study JSON schema")
}

pub fn run(input: &Path, output: &Path) -> Result<(), &'static str> {
    if !output.is_absolute() || output.as_os_str().len() > 4096 {
        return Err("study output needs a bounded absolute private path");
    }
    let bytes = read_private(input, MAX_MANIFEST)?;
    let report = assemble(&bytes)?;
    let mut encoded =
        serde_json::to_vec_pretty(&report).map_err(|_| "study output encoding failed")?;
    encoded.push(b'\n');
    aegis_core::secret_file::write_private_new(output, &encoded)
        .map_err(|_| "study output must be a new private file in trusted ancestry")
}

fn assemble(bytes: &[u8]) -> Result<Value, &'static str> {
    assemble_with_budget(bytes, MAX_TOTAL_EXPORT, MAX_ROWS)
}

// Private helper permits regression checks with small real file budgets. The
// sole product caller above supplies the fixed public admission ceilings.
fn assemble_with_budget(
    bytes: &[u8],
    mut remaining_bytes: usize,
    mut remaining_rows: usize,
) -> Result<Value, &'static str> {
    if bytes.len() > MAX_MANIFEST as usize {
        return Err("study manifest byte budget exceeded");
    }
    let manifest: Manifest = decode(bytes)?;
    if manifest.schema_version != 1
        || !(1..=16).contains(&manifest.policies.len())
        || !(1..=MAX_TRIALS).contains(&manifest.training_units.len())
    {
        return Err("invalid study version or policy/training budget");
    }
    let mut trial_count = 0usize;
    let mut policy_names = BTreeSet::new();
    for policy in &manifest.policies {
        trial_count = trial_count
            .checked_add(policy.trials.len())
            .ok_or("study trial budget overflow")?;
        if !identifier(&policy.name)
            || !policy_names.insert(&policy.name)
            || policy.trials.is_empty()
            || trial_count > MAX_TRIALS
            || policy.exports.is_empty()
            || policy.exports.len() > policy.trials.len()
        {
            return Err("invalid bounded policy/trial/export declarations");
        }
    }
    let bins_bytes = read_bound(&manifest.bins, MAX_SIDECAR)?;
    let bins: FrozenBins = decode(&bins_bytes)?;
    bins.validate(&json_digest(&manifest.training_units)?)?;
    let mut assembled_policies = Vec::new();
    let mut cost_bindings = Vec::new();
    for policy in &manifest.policies {
        let cost_bytes = read_bound(&policy.costs, MAX_SIDECAR)?;
        let costs: Costs = decode(&cost_bytes)?;
        if costs.schema_version != 1 || costs.rows.len() != policy.trials.len() {
            return Err("cost records must bind exactly one explicit cost per trial");
        }
        let mut by_key = BTreeMap::new();
        for cost in &costs.rows {
            if ![&cost.trial_id, &cost.network_id, &cost.time_holdout_id]
                .iter()
                .all(|id| identifier(id))
                || !cost.added_delay_ms.is_finite()
                || !(0.0..=3_600_000.0).contains(&cost.added_delay_ms)
                || by_key
                    .insert(
                        (
                            cost.trial_id.as_str(),
                            cost.network_id.as_str(),
                            cost.time_holdout_id.as_str(),
                        ),
                        cost,
                    )
                    .is_some()
            {
                return Err("invalid or duplicate explicit trial cost");
            }
        }
        let mut samples = Vec::new();
        for trial in &policy.trials {
            let cost = by_key
                .get(&trial.unit.key())
                .ok_or("missing explicit cost for paired trial")?;
            samples.push(json!({"label":trial.label,"feature":0,"added_bytes":cost.added_bytes,"added_delay_ms":cost.added_delay_ms}));
        }
        assembled_policies.push(json!({"name":policy.name,"samples":samples,
            "provenance":{"source_sha256":json_digest(policy)?,"sample_units":policy.trials.iter().map(|trial| &trial.unit).collect::<Vec<_>>()}}));
        cost_bindings.push(json!({"policy":policy.name,"cost_sha256":digest(&cost_bytes)}));
    }
    let mut assembled = json!({"alphabet":{"labels":2,"features":bins.upper_exclusive_edges.len()+1},
        "assume_iid_fixed_alphabet":false,"delta":0.05,"policies":assembled_policies,
        "provenance":{"schema_version":1,"frozen_bins_sha256":digest(&bins_bytes),
        "bins_frozen_unix_ms":bins.frozen_unix_ms,"training_units":manifest.training_units}});
    // Validate all existing pair/training/capture declarations before bulk export
    // I/O. Temporary feature0 values are never emitted as measurements.
    crate::privacy_frontier::privacy_frontier_report(&assembled)
        .map_err(|_| "study failed existing paired provenance admission")?;
    let mut export_bindings = Vec::new();
    let mut trial_measurements = Vec::new();
    for (policy_index, policy) in manifest.policies.iter().enumerate() {
        let mut export_ids = BTreeSet::new();
        let mut capture_exports = BTreeSet::new();
        for export in &policy.exports {
            if !identifier(&export.id) || !export_ids.insert(&export.id) {
                return Err("invalid or duplicate export identifier");
            }
            if !capture_exports.insert(&export.capture_sha256) {
                return Err(
                    "one declared capture must have exactly one retained export per policy",
                );
            }
            let indices: Vec<_> = policy
                .trials
                .iter()
                .enumerate()
                .filter(|(_, trial)| trial.export_id == export.id)
                .map(|(index, _)| index)
                .collect();
            if indices.is_empty() {
                return Err("unused packet export declaration");
            }
            let started_us = export
                .capture_started_unix_ms
                .checked_mul(1000)
                .ok_or("capture interval overflow")?;
            let finished_exclusive_us = export
                .capture_finished_unix_ms
                .checked_add(1)
                .and_then(|end| end.checked_mul(1000))
                .ok_or("capture interval overflow")?;
            let mut selections = Vec::new();
            for index in &indices {
                let trial = &policy.trials[*index];
                if trial.unit.capture_sha256 != export.capture_sha256
                    || trial.unit.network_id != export.network_id
                    || trial.unit.capture_started_unix_ms != export.capture_started_unix_ms
                    || trial.unit.capture_finished_unix_ms != export.capture_finished_unix_ms
                {
                    return Err("trial and export capture declarations disagree");
                }
                selections.push(Selection {
                    flow: trial.flow,
                    started_us: trial.window_started_unix_us,
                    finished_us: trial.window_finished_unix_us,
                });
            }
            // A bounded remainder is checked before the descriptor read, not
            // after retaining an arbitrarily large set of exports.
            let export_bytes = read_bound(&export.file, MAX_EXPORT.min(remaining_bytes as u64))?;
            remaining_bytes = remaining_bytes
                .checked_sub(export_bytes.len())
                .ok_or("combined export byte budget exceeded")?;
            let (stats, rows) = packet_rows::extract(
                &export_bytes,
                &selections,
                started_us,
                finished_exclusive_us,
                &mut remaining_rows,
            )?;
            let selected_rows: u64 = stats.iter().map(|stats| stats.selected_packet_rows).sum();
            export_bindings.push(json!({"policy":policy.name,"export_id":export.id,
                "export_sha256":digest(&export_bytes),"declared_capture_sha256":export.capture_sha256,
                "parsed_rows":rows,"unselected_rows":rows as u64-selected_rows}));
            for (index, stats) in indices.iter().zip(stats) {
                assembled["policies"][policy_index]["samples"][*index]["feature"] =
                    json!(bins.feature(stats.selected_wire_frame_bytes));
                trial_measurements.push(json!({"policy":policy.name,"trial_id":policy.trials[*index].unit.trial_id,
                    "network_id":policy.trials[*index].unit.network_id,"time_holdout_id":policy.trials[*index].unit.time_holdout_id,"stats":stats}));
            }
        }
        if policy
            .trials
            .iter()
            .any(|trial| !export_ids.contains(&trial.export_id))
        {
            return Err("trial refers to missing packet export");
        }
    }
    let frontier = crate::privacy_frontier::privacy_frontier_report(&assembled)
        .map_err(|_| "assembled study failed existing frontier admission")?;
    Ok(
        json!({"artifact_schema":"aegis_private_privacy_study_assembly_v1",
        "scope":"hash-bound private packet-field exports and frozen scalar bins; not capture-origin or independence proof",
        "source_kind":manifest.source_kind,"manifest_sha256":digest(bytes),
        "assembled_input":assembled,"frontier_report":frontier,
        "content_bindings":{"bins_sha256":digest(&bins_bytes),"costs":cost_bindings,"exports":export_bindings},
        "trial_measurements":trial_measurements,
        "declared_input_content_hashes_verified":true,"actual_bin_contents_validated":true,
        "capture_contents_verified":false,"export_capture_correspondence_verified":false,
        "trusted_freeze_time_proven":false,"bin_training_origin_verified":false,"cost_wire_measurement_verified":false,
        "statistical_independence_proven":false,"delivery_proven":false,"target_network_acceptance":false,
        "automatic_policy_adoption":false,"whole_flow_privacy_guarantee":false,"beta_exit":false}),
    )
}

#[cfg(test)]
#[path = "privacy_study/tests.rs"]
mod tests;
