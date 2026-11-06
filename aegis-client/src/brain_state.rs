//! Brain disk state is a separate, explicit privacy policy from diagnostics.
use aegis_core::{config_types::DirectSettings, AsyncStateStore, Mode};
use anyhow::Context;

pub async fn load_runtime(
    settings: &DirectSettings,
    mode: Mode,
    forensic: bool,
) -> anyhow::Result<AsyncStateStore> {
    // Decide before expanding or touching a path: even loading old snapshots
    // and key sidecars would cross the default RAM-only privacy boundary.
    if forensic || cfg!(forensic_safe) || !settings.persist_state || matches!(mode, Mode::Relay) {
        return Ok(AsyncStateStore::ephemeral());
    }
    let path = crate::runtime_paths::expand_tilde(&settings.state_path);
    AsyncStateStore::load(path.clone())
        .await
        .with_context(|| format!("state {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    async fn exercise_disk_boundary(mode: Mode, consent: bool, forensic: bool) {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("state.json");
        // Existing destination evidence must neither be loaded nor silently erased.
        let previous = br#"{"strategy_stats":{"prior-destination|relay":{}}}"#;
        std::fs::write(&path, previous).unwrap();
        let settings = DirectSettings {
            state_path: path.clone(),
            persist_state: consent,
            ..Default::default()
        };
        let store = load_runtime(&settings, mode, forensic).await.unwrap();
        assert!(store.snapshot().await.strategy_stats.is_empty());
        store
            .update(|snapshot| {
                snapshot
                    .strategy_stats
                    .insert("current-destination|relay".into(), Default::default());
            })
            .await;
        store.flush().await.unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), previous);
        assert_eq!(
            std::fs::read_dir(dir.path()).unwrap().count(),
            1,
            "no key sidecar, quarantine or replacement"
        );
    }

    #[tokio::test]
    async fn default_modes_keep_destination_learning_in_ram_and_preserve_existing_disk() {
        for mode in [Mode::Direct, Mode::Auto, Mode::Relay] {
            exercise_disk_boundary(mode, false, false).await;
        }
    }

    #[tokio::test]
    async fn relay_remains_ram_only_even_with_direct_persistence_consent() {
        exercise_disk_boundary(Mode::Relay, true, false).await;
    }

    #[tokio::test]
    async fn forensic_policy_overrides_direct_persistence_consent() {
        exercise_disk_boundary(Mode::Direct, true, true).await;
    }

    #[tokio::test]
    async fn valid_prior_destination_snapshot_is_not_loaded_without_consent() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("state.json");
        let mut previous = aegis_core::StateSnapshot::default();
        previous
            .strategy_stats
            .insert("prior-valid-destination|relay".into(), Default::default());
        let bytes = serde_json::to_vec(&previous).unwrap();
        std::fs::write(&path, &bytes).unwrap();
        let settings = DirectSettings {
            state_path: path.clone(),
            ..Default::default()
        };
        for mode in [Mode::Direct, Mode::Auto, Mode::Relay] {
            let store = load_runtime(&settings, mode, false).await.unwrap();
            assert!(store.snapshot().await.strategy_stats.is_empty());
            store.flush().await.unwrap();
        }
        assert_eq!(std::fs::read(&path).unwrap(), bytes);
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    #[tokio::test]
    async fn explicit_direct_consent_retains_disk_learning() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("state.json");
        let settings = DirectSettings {
            state_path: path.clone(),
            persist_state: true,
            ..Default::default()
        };
        let store = load_runtime(&settings, Mode::Direct, false).await.unwrap();
        store
            .update(|snapshot| {
                snapshot
                    .strategy_stats
                    .insert("opted-in-destination|direct".into(), Default::default());
            })
            .await;
        store.flush().await.unwrap();
        let restored = load_runtime(&settings, Mode::Direct, false).await.unwrap();
        let retained = restored
            .snapshot()
            .await
            .strategy_stats
            .contains_key("opted-in-destination|direct");
        if cfg!(forensic_safe) {
            assert!(
                !path.exists(),
                "compiled forensic policy also overrides direct consent"
            );
            assert!(!retained);
        } else {
            assert!(retained);
        }
    }
}
