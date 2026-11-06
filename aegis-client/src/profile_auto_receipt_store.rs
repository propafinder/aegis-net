//! Protected installed-receipt integration for the experimental AUTO pipeline.
//! This is a real nested transaction module, not a fake publication Context.
//! Source admission precedes custody; receipt sealing is separate from metadata
//! publication so the latter reconstructs a fresh authenticated RootContext.
use super::{authority::StageGuard, digest, refuse, Phase, Result, MAX_LEAVES, MAX_STAGE};
use crate::profile_auto_capture::{self as capture, GenerationRecord};
use crate::profile_auto_install_receipt::{
    current_utc_seconds, BinaryGeneration, CapturedBinary, CapturedProvenance, InstalledReceipt,
    Provenance,
};
use crate::profile_auto_prepare::OwnedTree;
use crate::profile_auto_publication::linux as fs;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

const INPUTS: &str = "input/install-receipt/inputs.json";
const SOURCE: &str = "input/install-receipt/provenance-generation.json";
const CANDIDATE: &str = "input/install-receipt/candidate-generation.json";
const RECIPE: &str = "accepted/install-receipt/recipe.json";
const RECEIPT: &str = "accepted/install-receipt/manifest.json";
const INSTALLED: &str = "accepted/install-receipt/installed-generation.json";
const RELATIVE_RECEIPT: &str = "install-manifest.json";
const BASE_PREFIX: &str = "accepted/payload/metadata";
const DIRECTORIES: &str = "accepted/directories/metadata.json";

pub(super) struct PrepareInputs<'a> {
    pub public_payload_root: &'a Path,
    pub candidate_binary: &'a Path,
    pub installed_binary: &'a Path,
    pub source_manifest_url: Option<&'a str>,
    pub source_release_channel: Option<&'a str>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Inputs {
    schema: u32,
    nonce: String,
    input_generation: String,
    planned_generation: String,
    public_payload_root: PathBuf,
    candidate_binary: PathBuf,
    installed_binary: PathBuf,
    operator_uid: u32,
    provenance: Provenance,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Recipe {
    schema: u32,
    nonce: String,
    input_generation: String,
    planned_generation: String,
    config_record_sha256: String,
    inputs_sha256: String,
    candidate_generation_sha256: String,
    receipt_sha256: String,
    installed_generation_sha256: String,
    base: BTreeMap<PathBuf, String>,
    files: BTreeMap<PathBuf, PathBuf>,
    directories_sha256: String,
}
fn failure<T>(_: T) -> String {
    refuse()
}
fn normalized(path: &Path) -> bool {
    super::absolute(path)
        && path
            .to_str()
            .is_some_and(|p| !p.chars().any(char::is_control))
}
fn bound(stage: &StageGuard, leaf: &Path) -> Result<Zeroizing<Vec<u8>>> {
    stage.store.revalidate()?;
    let bytes = stage.store.read(leaf)?;
    if stage.header.leaves.get(leaf) != Some(&digest(&bytes)) {
        return Err(refuse());
    }
    Ok(bytes)
}
fn binding(stage: &StageGuard, nonce: &str, input: &str, planned: &str) -> Result<()> {
    if stage.header.transaction_nonce != nonce
        || stage.header.input_generation != input
        || stage.header.planned_generation != planned
    {
        return Err(refuse());
    }
    Ok(())
}
fn inputs(stage: &StageGuard) -> Result<Inputs> {
    let result: Inputs =
        serde_json::from_slice(&bound(stage, Path::new(INPUTS))?).map_err(failure)?;
    binding(
        stage,
        &result.nonce,
        &result.input_generation,
        &result.planned_generation,
    )?;
    if result.schema != 1
        || result.operator_uid != stage.manifest.operator_uid
        || !normalized(&result.public_payload_root)
        || !normalized(&result.candidate_binary)
        || !normalized(&result.installed_binary)
        || result.candidate_binary == result.installed_binary
        || result.installed_binary.file_name() != Some(std::ffi::OsStr::new("aegis-client"))
        || !result
            .provenance
            .binds_manifest(&result.public_payload_root.join("bundle.manifest.json"))
    {
        return Err(refuse());
    }
    result.provenance.validate().map_err(failure)?;
    for target in [
        &stage.header.config_root,
        &stage.header.state_dir,
        &stage.header.metadata_dir,
    ] {
        if [
            &result.public_payload_root,
            &result.candidate_binary,
            &result.installed_binary,
        ]
        .iter()
        .any(|p| p.starts_with(target) || target.starts_with(p))
        {
            return Err(refuse());
        }
    }
    Ok(result)
}

pub(super) fn prepare_handoff_facts(
    stage: &StageGuard,
) -> Result<(PathBuf, PathBuf, String, String)> {
    revalidate_inputs(stage)?;
    let admitted = inputs(stage)?;
    let candidate: BinaryGeneration =
        serde_json::from_slice(&bound(stage, Path::new(CANDIDATE))?).map_err(failure)?;
    if !candidate.binds(&admitted.candidate_binary, admitted.operator_uid, false) {
        return Err(refuse());
    }
    candidate.validate_current().map_err(failure)?;
    let candidate_sha = candidate
        .fingerprint()
        .map_err(failure)?
        .sha256()
        .map_err(failure)?
        .to_owned();
    let provenance_sha = stage
        .header
        .leaves
        .get(Path::new(SOURCE))
        .ok_or_else(refuse)?
        .clone();
    Ok((
        admitted.candidate_binary,
        admitted.public_payload_root,
        candidate_sha,
        provenance_sha,
    ))
}
pub(super) fn active_input_facts(stage: &StageGuard) -> Result<serde_json::Value> {
    let (candidate_binary, public_payload_root, candidate_sha, provenance_sha) =
        prepare_handoff_facts(stage)?;
    Ok(serde_json::json!({
        "public_payload_root": public_payload_root,
        "candidate_binary": candidate_binary,
        "candidate_sha256": candidate_sha,
        "provenance_sha256": provenance_sha,
    }))
}
fn write_successor(
    stage: &mut StageGuard,
    files: BTreeMap<PathBuf, Zeroizing<Vec<u8>>>,
    recipe: bool,
) -> Result<()> {
    if stage
        .header
        .leaves
        .len()
        .checked_add(files.len())
        .is_none_or(|n| n > MAX_LEAVES)
        || files.keys().any(|p| stage.header.leaves.contains_key(p))
    {
        return Err(refuse());
    }
    let mut total = 0usize;
    for p in stage.header.leaves.keys() {
        total = total
            .checked_add(bound(stage, p)?.len())
            .ok_or_else(refuse)?;
    }
    for bytes in files.values() {
        total = total.checked_add(bytes.len()).ok_or_else(refuse)?;
    }
    if total > MAX_STAGE {
        return Err(refuse());
    }
    // No overwritten files. A failed partial private write is retained and
    // refuses subsequent conflicting attempt; it never publishes metadata.
    for (p, bytes) in &files {
        stage.store.write_new(p, bytes)?;
    }
    for (p, bytes) in files {
        stage.header.leaves.insert(p, digest(&bytes));
    }
    if recipe {
        stage.header.installed_receipt_recipe = Some(PathBuf::from(RECIPE));
    }
    stage.persist_header()
}
/// Must be called immediately after protected stage preparation and before
/// returning the stage path to the shell, while no active custody has occurred.
pub(super) fn admit_prepare(stage: &mut StageGuard, args: PrepareInputs<'_>) -> Result<()> {
    if unsafe { libc::geteuid() } != 0
        || stage.header.phase != Phase::Prepared
        || stage.header.pending.is_some()
        || stage.header.capture_started
        || stage.header.installed_receipt_recipe.is_some()
        || stage.header.leaves.contains_key(Path::new(INPUTS))
    {
        return Err(refuse());
    }
    if !normalized(args.public_payload_root)
        || !normalized(args.candidate_binary)
        || !normalized(args.installed_binary)
        || args.candidate_binary == args.installed_binary
        || args.installed_binary.file_name() != Some(std::ffi::OsStr::new("aegis-client"))
        || [
            &stage.header.config_root,
            &stage.header.state_dir,
            &stage.header.metadata_dir,
        ]
        .iter()
        .any(|target| {
            [
                args.public_payload_root,
                args.candidate_binary,
                args.installed_binary,
            ]
            .iter()
            .any(|p| p.starts_with(target) || target.starts_with(p))
        })
    {
        return Err(refuse());
    }
    let provenance = CapturedProvenance::capture(
        args.public_payload_root,
        stage.manifest.operator_uid,
        args.source_manifest_url,
        args.source_release_channel,
    )
    .map_err(failure)?;
    let candidate =
        CapturedBinary::capture(args.candidate_binary, stage.manifest.operator_uid, false)
            .map_err(failure)?;
    provenance
        .fields
        .admit_candidate(args.candidate_binary, candidate.fingerprint())
        .map_err(failure)?;
    let source = serde_json::to_vec(&provenance.generation().map_err(failure)?).map_err(failure)?;
    let candidate_record = candidate.generation_bytes().map_err(failure)?;
    // Validate deterministic record-size constraints before custody. This is
    // only a shape/capacity model, never a claim that installation occurred.
    let receipt_bound = InstalledReceipt::create(
        &provenance.fields,
        args.installed_binary,
        candidate.fingerprint(),
        candidate.fingerprint(),
        "2000-01-01T00:00:00Z",
    )
    .map_err(failure)?
    .bytes()
    .map_err(failure)?
    .len();
    let value = Inputs {
        schema: 1,
        nonce: stage.header.transaction_nonce.clone(),
        input_generation: stage.header.input_generation.clone(),
        planned_generation: stage.header.planned_generation.clone(),
        public_payload_root: args.public_payload_root.into(),
        candidate_binary: args.candidate_binary.into(),
        installed_binary: args.installed_binary.into(),
        operator_uid: stage.manifest.operator_uid,
        provenance: provenance.fields,
    };
    let mut files = BTreeMap::new();
    files.insert(
        PathBuf::from(INPUTS),
        Zeroizing::new(serde_json::to_vec(&value).map_err(failure)?),
    );
    files.insert(PathBuf::from(SOURCE), Zeroizing::new(source));
    files.insert(PathBuf::from(CANDIDATE), candidate_record);
    let base = base_metadata(stage)?;
    let provisional = Recipe {
        schema: 1,
        nonce: stage.header.transaction_nonce.clone(),
        input_generation: stage.header.input_generation.clone(),
        planned_generation: stage.header.planned_generation.clone(),
        config_record_sha256: "0".repeat(64),
        inputs_sha256: "0".repeat(64),
        candidate_generation_sha256: "0".repeat(64),
        receipt_sha256: "0".repeat(64),
        installed_generation_sha256: "0".repeat(64),
        files: metadata_files(&base)?,
        base,
        directories_sha256: "0".repeat(64),
    };
    let recipe_bound = serde_json::to_vec(&provisional).map_err(failure)?.len();
    let existing = stage.header.leaves.keys().try_fold(0usize, |sum, p| {
        sum.checked_add(bound(stage, p)?.len()).ok_or_else(refuse)
    })?;
    let proposed = files
        .values()
        .try_fold(0usize, |sum, b| sum.checked_add(b.len()).ok_or_else(refuse))?;
    if existing
        .checked_add(proposed)
        .and_then(|n| n.checked_add(receipt_bound))
        .and_then(|n| n.checked_add(recipe_bound))
        .and_then(|n| n.checked_add(32 * 1024))
        .is_none_or(|n| n > MAX_STAGE)
        || stage
            .header
            .leaves
            .len()
            .checked_add(6)
            .is_none_or(|n| n > MAX_LEAVES)
    {
        return Err(refuse());
    }
    candidate.revalidate().map_err(failure)?;
    // CapturedProvenance fields moved above; capture source is validated again
    // through its exact descriptor-minted record before any header admission.
    let source_record: GenerationRecord =
        serde_json::from_slice(files.get(Path::new(SOURCE)).ok_or_else(refuse)?)
            .map_err(failure)?;
    capture::reopen_generation(&source_record)
        .and_then(|g| g.revalidate())
        .map_err(failure)?;
    write_successor(stage, files, false)?;
    inputs(stage)?;
    revalidate_inputs(stage)
}
/// Invoke at every before-custody admission as well as before receipt sealing.
/// This metadata-only check never reloads candidate/provenance contents.
pub(super) fn revalidate_inputs(stage: &StageGuard) -> Result<()> {
    let admitted = inputs(stage)?;
    let source: GenerationRecord =
        serde_json::from_slice(&bound(stage, Path::new(SOURCE))?).map_err(failure)?;
    if source.original_source() != admitted.public_payload_root.join("bundle.manifest.json")
        || !matches!(source.role(),capture::InputRole::ExplicitBundleData{operator_uid,administrator_uid} if operator_uid==admitted.operator_uid && administrator_uid==0)
    {
        return Err(refuse());
    }
    capture::reopen_generation(&source)
        .and_then(|g| g.revalidate())
        .map_err(failure)?;
    let candidate: BinaryGeneration =
        serde_json::from_slice(&bound(stage, Path::new(CANDIDATE))?).map_err(failure)?;
    if !candidate.binds(&admitted.candidate_binary, admitted.operator_uid, false) {
        return Err(refuse());
    }
    admitted
        .provenance
        .admit_candidate(
            &admitted.candidate_binary,
            candidate.fingerprint().map_err(failure)?,
        )
        .map_err(failure)?;
    candidate.validate_current().map_err(failure)
}
fn base_metadata(stage: &StageGuard) -> Result<BTreeMap<PathBuf, String>> {
    let mut result = BTreeMap::new();
    for (p, hash) in &stage.header.leaves {
        if let Ok(relative) = p.strip_prefix(BASE_PREFIX) {
            if !super::relative(relative) || result.insert(relative.into(), hash.clone()).is_some()
            {
                return Err(refuse());
            }
        }
    }
    Ok(result)
}
fn metadata_files(base: &BTreeMap<PathBuf, String>) -> Result<BTreeMap<PathBuf, PathBuf>> {
    let mut files = BTreeMap::new();
    for relative in base.keys() {
        if !super::relative(relative) {
            return Err(refuse());
        }
        files.insert(relative.clone(), Path::new(BASE_PREFIX).join(relative));
    }
    files.insert(PathBuf::from(RELATIVE_RECEIPT), PathBuf::from(RECEIPT));
    Ok(files)
}
fn config_sha(stage: &StageGuard) -> Result<String> {
    stage
        .header
        .active_records
        .get("config")
        .and_then(|p| stage.header.current_records.get(p))
        .filter(|s| s.phase == "config" || s.phase == "projection")
        .map(|s| s.sha256.clone())
        .ok_or_else(refuse)
}
fn recipe(stage: &StageGuard) -> Result<Recipe> {
    if stage.header.installed_receipt_recipe.as_deref() != Some(Path::new(RECIPE)) {
        return Err(refuse());
    }
    let r: Recipe = serde_json::from_slice(&bound(stage, Path::new(RECIPE))?).map_err(failure)?;
    binding(stage, &r.nonce, &r.input_generation, &r.planned_generation)?;
    let config = stage
        .header
        .active_records
        .get("config")
        .and_then(|p| stage.header.current_records.get(p))
        .ok_or_else(refuse)?;
    if !((matches!(config.phase.as_str(), "config" | "projection")
        && config.sha256 == r.config_record_sha256)
        || (config.phase == "projection"
            && config.predecessor_sha256.as_deref() == Some(r.config_record_sha256.as_str())))
    {
        return Err(refuse());
    }
    if r.schema != 1
        || r.base != base_metadata(stage)?
        || r.inputs_sha256 != digest(&bound(stage, Path::new(INPUTS))?)
        || r.candidate_generation_sha256 != digest(&bound(stage, Path::new(CANDIDATE))?)
        || r.receipt_sha256 != digest(&bound(stage, Path::new(RECEIPT))?)
        || r.installed_generation_sha256 != digest(&bound(stage, Path::new(INSTALLED))?)
        || r.directories_sha256 != digest(&bound(stage, Path::new(DIRECTORIES))?)
        || r.files != metadata_files(&r.base)?
    {
        return Err(refuse());
    }
    InstalledReceipt::validate_readback(&bound(stage, Path::new(RECEIPT))?).map_err(failure)?;
    Ok(r)
}
/// Seals one new protected metadata epoch; does not publish the target. Caller
/// must drop old RootContext and create a fresh one for publish-metadata.
pub(super) fn seal(stage: &mut StageGuard) -> Result<()> {
    if unsafe { libc::geteuid() } != 0
        || stage.header.phase != Phase::Config
        || stage.header.pending.is_some()
        || stage.header.capture_started
    {
        return Err(refuse());
    }
    revalidate_inputs(stage)?;
    if stage.header.installed_receipt_recipe.is_some() {
        let r = recipe(stage)?;
        if r.config_record_sha256 != config_sha(stage)? {
            return Err(refuse());
        }
        return verify_installed(stage);
    }
    let admitted = inputs(stage)?;
    let candidate: BinaryGeneration =
        serde_json::from_slice(&bound(stage, Path::new(CANDIDATE))?).map_err(failure)?;
    let installed =
        CapturedBinary::capture(&admitted.installed_binary, 0, true).map_err(failure)?;
    let receipt = InstalledReceipt::create(
        &admitted.provenance,
        &admitted.installed_binary,
        candidate.fingerprint().map_err(failure)?,
        installed.fingerprint(),
        &current_utc_seconds().map_err(failure)?,
    )
    .map_err(failure)?
    .bytes()
    .map_err(failure)?;
    let generation = installed.generation_bytes().map_err(failure)?;
    let base = base_metadata(stage)?;
    let files = metadata_files(&base)?;
    let r = Recipe {
        schema: 1,
        nonce: stage.header.transaction_nonce.clone(),
        input_generation: stage.header.input_generation.clone(),
        planned_generation: stage.header.planned_generation.clone(),
        config_record_sha256: config_sha(stage)?,
        inputs_sha256: digest(&bound(stage, Path::new(INPUTS))?),
        candidate_generation_sha256: digest(&bound(stage, Path::new(CANDIDATE))?),
        receipt_sha256: digest(&receipt),
        installed_generation_sha256: digest(&generation),
        base,
        files,
        directories_sha256: digest(&bound(stage, Path::new(DIRECTORIES))?),
    };
    let mut leaves = BTreeMap::new();
    leaves.insert(PathBuf::from(RECEIPT), receipt);
    leaves.insert(PathBuf::from(INSTALLED), generation);
    leaves.insert(
        PathBuf::from(RECIPE),
        Zeroizing::new(serde_json::to_vec(&r).map_err(failure)?),
    );
    installed.revalidate().map_err(failure)?;
    revalidate_inputs(stage)?;
    write_successor(stage, leaves, true)?;
    verify_installed(stage)
}
pub(super) fn verify_installed(stage: &StageGuard) -> Result<()> {
    let admitted = inputs(stage)?;
    let actual: BinaryGeneration =
        serde_json::from_slice(&bound(stage, Path::new(INSTALLED))?).map_err(failure)?;
    if !actual.binds(&admitted.installed_binary, 0, true) {
        return Err(refuse());
    }
    actual.validate_current().map_err(failure)
}
/// The active observer consumes the protected installed record, never a
/// caller pathname/hash or a fresh capture of the currently selected binary.
pub(super) fn installed_generation(stage: &StageGuard) -> Result<BinaryGeneration> {
    verify_activation(stage)?;
    let admitted = inputs(stage)?;
    let actual: BinaryGeneration =
        serde_json::from_slice(&bound(stage, Path::new(INSTALLED))?).map_err(failure)?;
    if !actual.binds(&admitted.installed_binary, 0, true) {
        return Err(refuse());
    }
    actual.validate_current().map_err(failure)?;
    Ok(actual)
}
/// Exact argv of the compiled fixed unit from the already admitted recipe.
pub(super) fn installed_command_line(stage: &StageGuard) -> Result<Vec<u8>> {
    verify_activation(stage)?;
    let admitted = inputs(stage)?;
    let config = stage.header.config_root.join("aegis.toml");
    let mut command = Vec::new();
    for word in [
        admitted.installed_binary.to_str().ok_or_else(refuse)?,
        "--config",
        config.to_str().ok_or_else(refuse)?,
        "--runtime-events-jsonl",
        stage.header.runtime_events.to_str().ok_or_else(refuse)?,
    ] {
        command.extend_from_slice(word.as_bytes());
        command.push(0);
    }
    Ok(command)
}
/// Hook only for accepted AdministratorMetadata, never input/rollback trees.
pub(super) fn accepted_metadata_tree(stage: &StageGuard) -> Result<OwnedTree> {
    let r = recipe(stage)?;
    let mut files = BTreeMap::new();
    let mut total = 0usize;
    for (relative, leaf) in r.files {
        let b = bound(stage, &leaf)?;
        total = total.checked_add(b.len()).ok_or_else(refuse)?;
        if total > 64 * 1024 * 1024 || files.len() >= 1024 {
            return Err(refuse());
        }
        files.insert(relative, b);
    }
    let directories: Vec<PathBuf> =
        serde_json::from_slice(&bound(stage, Path::new(DIRECTORIES))?).map_err(failure)?;
    let mut set = BTreeSet::new();
    for d in directories {
        if !d.as_os_str().is_empty() && (!super::relative(&d) || !set.insert(d)) {
            return Err(refuse());
        }
    }
    if files.len() + set.len() > 1024 || files.keys().any(|p| set.contains(p)) {
        return Err(refuse());
    }
    for leaf in files.keys().chain(set.iter()) {
        let mut parent = leaf.parent();
        while let Some(p) = parent {
            if p.as_os_str().is_empty() {
                break;
            }
            if !set.contains(p) {
                return Err(refuse());
            }
            parent = p.parent();
        }
    }
    Ok(OwnedTree {
        files,
        directories: set,
    })
}
/// Owned published receipt readback plus same actual installed generation, not
/// a hash comparison against an untrusted current file or stale cached Context.
pub(super) fn verify_activation(stage: &StageGuard) -> Result<()> {
    if !matches!(stage.header.phase, Phase::Metadata | Phase::Finalized)
        || stage.header.pending.is_some()
    {
        return Err(refuse());
    }
    let _ = recipe(stage)?;
    verify_installed(stage)?;
    let target = fs::Target::open(&stage.header.metadata_dir).map_err(failure)?;
    let record = stage.publication_record("metadata")?;
    let receipt = fs::reopen_own_receipt(&target, &record).map_err(failure)?;
    let tree = accepted_metadata_tree(stage)?;
    if fs::current_leaf_names(&target, &receipt).map_err(failure)?
        != tree.files.keys().cloned().collect()
    {
        return Err(refuse());
    }
    for (relative, expected) in tree.files {
        let actual = fs::read_current_leaf(&target, &receipt, &relative).map_err(failure)?;
        if actual.as_slice() != expected.as_slice() {
            return Err(refuse());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn actual_metadata_recipe_replaces_only_fixed_receipt_and_preserves_unknown_members() {
        let base = BTreeMap::from([
            (PathBuf::from("wide-profile.json"), "a".repeat(64)),
            (PathBuf::from("unknown/operator-note.txt"), "b".repeat(64)),
            (PathBuf::from(RELATIVE_RECEIPT), "c".repeat(64)),
        ]);
        let actual = metadata_files(&base).unwrap();
        assert_eq!(actual.len(), 3);
        assert_eq!(
            actual.get(Path::new(RELATIVE_RECEIPT)),
            Some(&PathBuf::from(RECEIPT))
        );
        assert_eq!(
            actual.get(Path::new("unknown/operator-note.txt")),
            Some(&PathBuf::from(
                "accepted/payload/metadata/unknown/operator-note.txt"
            ))
        );
        assert_eq!(base.get(Path::new(RELATIVE_RECEIPT)), Some(&"c".repeat(64)));
    }
    #[test]
    fn actual_metadata_recipe_adds_fresh_receipt_once_and_rejects_traversal() {
        let base = BTreeMap::from([(PathBuf::from("wide-profile.json"), "a".repeat(64))]);
        let actual = metadata_files(&base).unwrap();
        assert_eq!(actual.len(), 2);
        for illegal in ["../outside", "/outside", ""] {
            let wrong = BTreeMap::from([(PathBuf::from(illegal), "a".repeat(64))]);
            assert!(metadata_files(&wrong).is_err());
        }
    }
}
