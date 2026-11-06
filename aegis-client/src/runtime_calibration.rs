//! Explicit public calibration input is separate from private destination history.
use aegis_core::{
    config_types::DirectSettings, AsyncStateStore, ExternalCalibrationSnapshot, Mode,
};
use anyhow::{ensure, Context};
use std::fs::OpenOptions;
use std::io::Read;
use std::path::Path;

const MAX_BYTES: u64 = 1024 * 1024;
const MAX_ENTRIES: usize = 256;
const MAX_IDENTIFIER_BYTES: usize = 256;
const MAX_TEXT_BYTES: usize = 1024;

pub(crate) fn read_snapshot(path: &Path) -> anyhow::Result<ExternalCalibrationSnapshot> {
    let path = crate::config::expand_tilde(path);
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    #[cfg(windows)]
    aegis_core::windows_file::reject_reparse_ancestry(&path)?;
    let file = options
        .open(&path)
        .with_context(|| format!("open public calibration {}", path.display()))?;
    let metadata = file.metadata()?;
    ensure!(
        metadata.is_file() && metadata.len() <= MAX_BYTES,
        "public calibration must be a regular file no larger than 1 MiB"
    );
    let mut bytes = Vec::new();
    file.take(MAX_BYTES + 1).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 <= MAX_BYTES,
        "public calibration exceeds 1 MiB"
    );
    let value: serde_json::Value =
        serde_json::from_slice(&bytes).context("parse public calibration JSON")?;
    ensure!(
        value
            .get("schema_version")
            .and_then(serde_json::Value::as_u64)
            == Some(1),
        "public calibration requires schema_version=1"
    );
    let snapshot = crate::parse_external_calibration_snapshot(value)?;
    validate_snapshot(&snapshot)?;
    Ok(snapshot)
}

fn bounded_text(text: &str, limit: usize) -> anyhow::Result<()> {
    ensure!(
        text.len() <= limit,
        "public calibration text exceeds its bound"
    );
    Ok(())
}

fn identifier(text: &str) -> anyhow::Result<()> {
    ensure!(!text.is_empty(), "public calibration identifier is empty");
    bounded_text(text, MAX_IDENTIFIER_BYTES)
}

fn unit_score(value: f64) -> anyhow::Result<()> {
    ensure!(
        value.is_finite() && (0.0..=1.0).contains(&value),
        "public calibration score must be finite and between zero and one"
    );
    Ok(())
}

fn validate_snapshot(snapshot: &ExternalCalibrationSnapshot) -> anyhow::Result<()> {
    ensure!(
        snapshot.schema_version == 1,
        "unsupported public calibration schema"
    );
    ensure!(
        snapshot.witness.len() <= MAX_ENTRIES
            && snapshot.adversarial.len() <= MAX_ENTRIES
            && snapshot.knowledge.len() <= MAX_ENTRIES
            && snapshot.verdict.reasons.len() <= 64,
        "public calibration collection exceeds its bound"
    );
    ensure!(
        snapshot.freshness_half_life_secs != Some(0),
        "public calibration half-life must be positive"
    );
    bounded_text(&snapshot.source, MAX_TEXT_BYTES)?;
    bounded_text(&snapshot.verdict.status, MAX_IDENTIFIER_BYTES)?;
    for reason in &snapshot.verdict.reasons {
        bounded_text(reason, MAX_TEXT_BYTES)?;
    }
    for witness in &snapshot.witness {
        identifier(&witness.label)?;
        for score in [
            witness.combined_avg,
            witness.ja3_present_avg,
            witness.alpn_match_avg,
            witness.sni_structure_avg,
        ] {
            unit_score(score)?;
        }
    }
    for adversarial in &snapshot.adversarial {
        identifier(&adversarial.transport)?;
        for score in [adversarial.pass_rate, adversarial.threshold]
            .into_iter()
            .flatten()
        {
            unit_score(score)?;
        }
    }
    for prior in &snapshot.knowledge {
        identifier(&prior.target_class)?;
        if let Some(region) = &prior.region_id {
            bounded_text(region, MAX_IDENTIFIER_BYTES)?;
        }
        unit_score(prior.score)?;
        unit_score(prior.confidence)?;
    }
    Ok(())
}

pub(crate) async fn load_runtime(
    settings: &DirectSettings,
    mode: Mode,
    forensic: bool,
    calibration: Option<&ExternalCalibrationSnapshot>,
) -> anyhow::Result<AsyncStateStore> {
    let store = crate::brain_state::load_runtime(settings, mode, forensic).await?;
    if let Some(snapshot) = calibration {
        store
            .update(|state| state.external_calibration = Some(snapshot.clone()))
            .await;
        // No flush: Relay and forensic stores remain ephemeral. Import only the
        // explicit public signal, never learned destination state from its file.
        crate::runtime_event_stream::emit_external_calibration_applied(snapshot);
        for prior in &snapshot.knowledge {
            crate::runtime_event_stream::emit_knowledge_prior_applied(prior);
        }
    }
    Ok(store)
}

#[cfg(test)]
#[path = "runtime_calibration_tests.rs"]
mod tests;
