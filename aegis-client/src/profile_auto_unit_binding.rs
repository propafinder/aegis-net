//! Actual protected fixed-unit namespace admission for the private v2 worker.
//! Original namespace may be sealed only by the held-lock kernel/manager capture.
//! Prepared-new namespace remains unavailable until the owned policy publisher
//! supplies its actual complete receipts; this module has no public hash setter.
use super::{authority::StageGuard, digest, refuse, Phase, Result};
use crate::profile_auto_stopped_service::InstallLock;
use crate::profile_auto_unit_namespace::{NamespaceRecord, UnitNamespaceSnapshot};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
const OLD: &str = "input/unit-target/namespace.json";
const NEW: &str = "accepted/unit-target/namespace.json";
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SealedNamespace {
    schema: u32,
    nonce: String,
    input_generation: String,
    planned_generation: String,
    namespace_generation: String,
    record: NamespaceRecord,
}
pub(super) fn admit_original(stage: &mut StageGuard, lock: &InstallLock) -> Result<()> {
    lock.revalidate().map_err(|_| refuse())?;
    stage.store.revalidate()?;
    if stage.header.old_unit_namespace.is_some() {
        let record = read(stage, false)?;
        UnitNamespaceSnapshot::reopen(&record, lock)
            .and_then(|s| s.revalidate(lock))
            .map_err(|_| refuse())?;
        return Ok(());
    }
    if stage.header.phase != Phase::Prepared
        || stage.header.pending.is_some()
        || stage.header.service_uid.is_some()
        || !stage.header.active_records.is_empty()
    {
        return Err(refuse());
    }
    let captured = UnitNamespaceSnapshot::capture(lock).map_err(|_| refuse())?;
    let sealed = SealedNamespace {
        schema: 1,
        nonce: stage.header.transaction_nonce.clone(),
        input_generation: stage.header.input_generation.clone(),
        planned_generation: stage.header.planned_generation.clone(),
        namespace_generation: captured.record().generation().to_owned(),
        record: captured.record().clone(),
    };
    let bytes = serde_json::to_vec(&sealed).map_err(|_| refuse())?;
    if bytes.len() > 2 * 1024 * 1024 {
        return Err(refuse());
    }
    captured.revalidate(lock).map_err(|_| refuse())?;
    stage.revalidate_originals()?;
    stage.store.write_new(Path::new(OLD), &bytes)?;
    stage
        .header
        .leaves
        .insert(PathBuf::from(OLD), digest(&bytes));
    stage.header.old_unit_namespace = Some(OLD.into());
    stage.persist_header()?;
    captured.revalidate(lock).map_err(|_| refuse())
}
pub(super) fn read(stage: &StageGuard, prepared: bool) -> Result<NamespaceRecord> {
    stage.store.revalidate()?;
    let (pointer, fixed) = if prepared {
        (&stage.header.new_unit_namespace, NEW)
    } else {
        (&stage.header.old_unit_namespace, OLD)
    };
    if pointer.as_deref() != Some(Path::new(fixed)) {
        return Err(refuse());
    }
    let bytes = stage.store.read(Path::new(fixed))?;
    if bytes.len() > 2 * 1024 * 1024
        || stage.header.leaves.get(Path::new(fixed)) != Some(&digest(&bytes))
    {
        return Err(refuse());
    }
    let record: SealedNamespace = serde_json::from_slice(&bytes).map_err(|_| refuse())?;
    if record.schema != 1
        || record.nonce != stage.header.transaction_nonce
        || record.input_generation != stage.header.input_generation
        || record.planned_generation != stage.header.planned_generation
        || record.namespace_generation != record.record.generation()
        || record.record.fixed_unit() != "aegis-client.service"
    {
        return Err(refuse());
    }
    Ok(record.record)
}
