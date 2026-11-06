//! Async batch persistence для State v2.
//!
//! Отличие от v1 (`state.rs`):
//! - `enqueue_update()` — обновление в памяти (мгновенно, без I/O)
//! - `flush()` — async запись на диск (вызывается по таймеру или при shutdown)
//! - Serialization/key/seal preparation and private writer I/O run in blocking
//!   tasks under the same flush lease. Entry limits are not heap/latency limits.

use super::bounds::{BoundedSnapshot, StateTouches};
use super::schema::{StateSnapshot, StrategyStatsV2};
use crate::error::AegisError;
use crate::state::{StateFile, StrategyStats};
use crate::state_secret::{
    ensure_private_parent_dir_async, maybe_decrypt_state_blob, seal_state_blob,
    write_private_file_async,
};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::AsyncReadExt;
use tokio::sync::RwLock;

/// Async state store с batch persistence.
#[derive(Clone)]
pub struct AsyncStateStore {
    inner: Arc<Inner>,
}

struct Inner {
    path: PathBuf,
    snapshot: RwLock<BoundedSnapshot>,
    dirty: AtomicBool,
    revision: AtomicU64,
    flush_lock: Arc<tokio::sync::Mutex<()>>,
    /// Audit F4: forensic-safe RAM-only store — never reads from or writes to
    /// disk, so the Brain leaves no persistent activity map (hashed target
    /// hosts + cleartext dst subnets + timestamps) that a seized machine could
    /// mine. Cross-session learning is intentionally sacrificed for privacy.
    ephemeral: bool,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum FlushPreparationPhase {
    Serialize,
    Seal,
}

struct PreparedFlush {
    out: Vec<u8>,
    revision: u64,
    lease: tokio::sync::OwnedMutexGuard<()>,
}

impl AsyncStateStore {
    /// Загрузить state из файла (или создать пустой).
    pub async fn load(path: PathBuf) -> Result<Self, AegisError> {
        let _ = ensure_private_parent_dir_async(&path).await;
        let snapshot = if path.exists() {
            let file = tokio::fs::File::open(&path).await.map_err(AegisError::Io)?;
            let bytes = read_bounded_state(file).await?;
            let (bytes, decrypted) = prepare_loaded_decryption(path.clone(), bytes).await?;
            match decrypted {
                Ok(Some(decrypted)) => prepare_loaded_snapshot(decrypted).await?,
                Ok(None) => prepare_loaded_snapshot(bytes).await?,
                // An encrypted state without any matching master-key source is
                // unrecoverable. This can be left behind by an interrupted or
                // old uninstall/reinstall cycle. Preserve it for forensics, but
                // do not brick the network client forever: quarantine the exact
                // blob atomically and start with an empty Brain state. All other
                // crypto/I/O failures remain fatal.
                Err(AegisError::Config(reason)) if reason == "state_master_key_unavailable" => {
                    let quarantine = orphaned_state_quarantine_path(&path);
                    tokio::fs::rename(&path, &quarantine)
                        .await
                        .map_err(AegisError::Io)?;
                    tracing::warn!(
                        event_code = "state_orphaned_key_quarantined",
                        state_path = %path.display(),
                        quarantine_path = %quarantine.display(),
                        "encrypted Brain state had no matching master key; preserved the unreadable blob and started with empty state"
                    );
                    BoundedSnapshot::new(StateSnapshot::default())
                }
                Err(err) => return Err(err),
            }
        } else {
            BoundedSnapshot::new(StateSnapshot::default())
        };

        Ok(Self {
            inner: Arc::new(Inner {
                path,
                snapshot: RwLock::new(snapshot),
                dirty: AtomicBool::new(false),
                revision: AtomicU64::new(0),
                flush_lock: Arc::new(tokio::sync::Mutex::new(())),
                ephemeral: false,
            }),
        })
    }

    /// Audit F4: forensic-safe RAM-only store. Starts empty, never touches disk
    /// (`flush` is a no-op). Use on hostile/seizable hosts so the Brain's
    /// per-target statistics never persist as an activity trail.
    pub fn ephemeral() -> Self {
        Self {
            inner: Arc::new(Inner {
                path: PathBuf::new(),
                snapshot: RwLock::new(BoundedSnapshot::new(StateSnapshot::default())),
                dirty: AtomicBool::new(false),
                revision: AtomicU64::new(0),
                flush_lock: Arc::new(tokio::sync::Mutex::new(())),
                ephemeral: true,
            }),
        }
    }

    /// Получить read-only снимок (не блокирует).
    pub async fn snapshot(&self) -> StateSnapshot {
        self.inner.snapshot.read().await.snapshot.clone()
    }

    /// Обновить state в памяти. Мгновенно, без I/O.
    pub async fn update<F>(&self, f: F)
    where
        F: FnOnce(&mut StateSnapshot),
    {
        self.update_touched(|snapshot, _| f(snapshot)).await;
    }

    // Real Brain producers explicitly mark modified rows, including existing
    // entries. Opaque public updates discover new rows but cannot infer writes
    // to existing values. Mutation, retention and revision share one lock.
    pub(crate) async fn update_touched<F>(&self, f: F)
    where
        F: FnOnce(&mut StateSnapshot, &mut StateTouches),
    {
        let mut state = self.inner.snapshot.write().await;
        let mut touched = StateTouches::default();
        f(&mut state.snapshot, &mut touched);
        let BoundedSnapshot { snapshot, bounds } = &mut *state;
        bounds.enforce_update(snapshot, &touched);
        self.inner.revision.fetch_add(1, Ordering::Relaxed);
        self.inner.dirty.store(true, Ordering::Relaxed);
    }

    /// Записать на диск если dirty. Async I/O.
    pub async fn flush(&self) -> Result<(), AegisError> {
        self.flush_with_writer(|path, out, lease| async move {
            write_private_file_async(&path, out, lease).await
        })
        .await
    }

    async fn flush_with_writer<F, W>(&self, writer: F) -> Result<(), AegisError>
    where
        F: FnOnce(PathBuf, Vec<u8>, tokio::sync::OwnedMutexGuard<()>) -> W,
        W: std::future::Future<Output = Result<tokio::sync::OwnedMutexGuard<()>, AegisError>>,
    {
        self.flush_with_preparation_observer(writer, |_| {}).await
    }

    async fn flush_with_preparation_observer<F, W, P>(
        &self,
        writer: F,
        observer: P,
    ) -> Result<(), AegisError>
    where
        F: FnOnce(PathBuf, Vec<u8>, tokio::sync::OwnedMutexGuard<()>) -> W,
        W: std::future::Future<Output = Result<tokio::sync::OwnedMutexGuard<()>, AegisError>>,
        P: FnMut(FlushPreparationPhase) + Send + 'static,
    {
        // Audit F4: forensic-safe RAM-only store never writes to disk.
        if self.inner.ephemeral {
            return Ok(());
        }
        let lease = self.inner.flush_lock.clone().lock_owned().await;
        if !self.inner.dirty.load(Ordering::Relaxed) {
            return Ok(());
        }
        let PreparedFlush {
            out,
            revision,
            lease,
        } = Self::prepare_flush(self.inner.clone(), lease, observer).await?;
        let _lease = writer(self.inner.path.clone(), out, lease).await?;
        // Synchronize this check/clear with update's write lock. An update
        // during I/O must remain dirty even though the older snapshot persisted.
        let _snap = self.inner.snapshot.read().await;
        if self.inner.revision.load(Ordering::Relaxed) == revision {
            self.inner.dirty.store(false, Ordering::Relaxed);
        }
        Ok(())
    }

    async fn prepare_flush<P>(
        inner: Arc<Inner>,
        lease: tokio::sync::OwnedMutexGuard<()>,
        mut observer: P,
    ) -> Result<PreparedFlush, AegisError>
    where
        P: FnMut(FlushPreparationPhase) + Send + 'static,
    {
        // The same store authority and flush lease stay with preparation even
        // when its async waiter is cancelled. No snapshot/revision is cloned.
        tokio::task::spawn_blocking(move || {
            let snap = inner.snapshot.blocking_read();
            observer(FlushPreparationPhase::Serialize);
            let json = serde_json::to_vec_pretty(&snap.snapshot)?;
            if json.len() as u64 > STATE_FILE_LIMIT {
                // Refuse before key/seal work. Cardinality does not bound strings
                // or the synchronous serialization allocation itself.
                return Err(AegisError::Config("state_snapshot_file_too_large".into()));
            }
            let revision = inner.revision.load(Ordering::Relaxed);
            drop(snap); // освободить read lock до I/O
            observer(FlushPreparationPhase::Seal);
            let out = seal_state_blob(&inner.path, &json)?;
            if out.len() as u64 > STATE_FILE_LIMIT {
                // Keep the old blob and dirty revision rather than publish a file
                // which the same actual load ceiling must reject next startup.
                return Err(AegisError::Config("state_snapshot_file_too_large".into()));
            }
            Ok(PreparedFlush {
                out,
                revision,
                lease,
            })
        })
        .await
        .map_err(|_| AegisError::Config("state_prepare_join_error".into()))?
    }

    /// Dirty flag (для мониторинга).
    pub fn is_dirty(&self) -> bool {
        self.inner.dirty.load(Ordering::Relaxed)
    }
}

// Apply the ceiling to actual descriptor bytes, including a sealed envelope.
// Metadata alone cannot prevent a file growing between stat and read.
const STATE_FILE_LIMIT: u64 = 16 * 1024 * 1024;
async fn read_bounded_state(
    reader: impl tokio::io::AsyncRead + Unpin,
) -> Result<Vec<u8>, AegisError> {
    let mut bytes = Vec::new();
    reader
        .take(STATE_FILE_LIMIT + 1)
        .read_to_end(&mut bytes)
        .await
        .map_err(AegisError::Io)?;
    if bytes.len() as u64 > STATE_FILE_LIMIT {
        return Err(AegisError::Config("state_snapshot_file_too_large".into()));
    }
    Ok(bytes)
}

fn orphaned_state_quarantine_path(path: &std::path::Path) -> PathBuf {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("state");
    path.with_file_name(format!(
        "{file_name}.orphaned-key.{}.{}",
        std::process::id(),
        timestamp
    ))
}

type PreparedDecryption<B> = (B, Result<Option<Vec<u8>>, AegisError>);

// Own the input/path across the entire synchronous key lookup and AEAD call.
// A started blocking worker is not abortable; its original crypto result and
// bytes return together. State quarantine remains with the async load caller.
async fn prepare_loaded_decryption<B>(
    path: PathBuf,
    bytes: B,
) -> Result<PreparedDecryption<B>, AegisError>
where
    B: AsRef<[u8]> + Send + 'static,
{
    tokio::task::spawn_blocking(move || {
        let decrypted = maybe_decrypt_state_blob(&path, bytes.as_ref());
        (bytes, decrypted)
    })
    .await
    .map_err(|_| AegisError::Config("state_decryption_load_worker_failed".into()))
}

// Only pure parsing, legacy migration and initial retention normalization move
// here. Decryption has its own worker; quarantine stays with the load caller.
// Owned input avoids another plaintext copy; a started worker is not abortable.
async fn prepare_loaded_snapshot<B>(bytes: B) -> Result<BoundedSnapshot, AegisError>
where
    B: AsRef<[u8]> + Send + 'static,
{
    tokio::task::spawn_blocking(move || BoundedSnapshot::new(parse_snapshot_bytes(bytes.as_ref())))
        .await
        .map_err(|_| AegisError::Config("state_snapshot_load_worker_failed".into()))
}

fn parse_snapshot_bytes(bytes: &[u8]) -> StateSnapshot {
    if let Ok(snapshot) = serde_json::from_slice::<StateSnapshot>(bytes) {
        return snapshot;
    }
    if let Ok(legacy) = serde_json::from_slice::<StateFile>(bytes) {
        return migrate_legacy_state(legacy);
    }
    StateSnapshot::default()
}

fn migrate_legacy_state(legacy: StateFile) -> StateSnapshot {
    let mut snapshot = StateSnapshot::default();
    for (key_hash, strategies) in legacy.entries {
        for (strategy, stats) in strategies {
            snapshot.strategy_stats.insert(
                legacy_strategy_entry_key(&key_hash, &strategy),
                migrate_legacy_stats(stats),
            );
        }
    }
    snapshot
}

fn legacy_strategy_entry_key(key_hash: &str, strategy: &str) -> String {
    format!("{key_hash}|{strategy}")
}

fn migrate_legacy_stats(stats: StrategyStats) -> StrategyStatsV2 {
    let confidence = stats.confidence.clamp(0.0, 1.0);
    let trials = ((confidence * 10.0).round() as u64).max(1);
    let successes = (stats.success_rate.clamp(0.0, 1.0) * trials as f64).round() as u64;
    let dpi_blocks = matches!(stats.last_rst_source.as_deref(), Some("Dpi" | "dpi")) as u64;
    StrategyStatsV2 {
        trials,
        successes,
        degraded: 0,
        freezes: 0,
        timeouts: 0,
        dpi_blocks,
        mean_latency_ms: stats.avg_handshake_ms.max(0.0),
        mean_session_bytes: 0.0,
        fitness_score: stats.score().clamp(0.0, 1.0),
        last_signal: None,
        last_updated_unix_ms: None,
    }
}

#[cfg(test)]
#[path = "bounds_tests.rs"]
mod bounds_tests;

#[cfg(test)]
#[path = "retention_tests.rs"]
mod retention_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::{StateFile, StrategyStats};
    use tempfile::TempDir;

    #[tokio::test]
    async fn update_during_flush_remains_dirty_and_survives_next_flush() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("state.json");
        let store = AsyncStateStore::load(path.clone()).await.unwrap();
        store
            .update(|snap| {
                snap.strategy_stats
                    .insert("before".into(), Default::default());
            })
            .await;
        let writer_store = store.clone();
        let (captured_tx, captured_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = tokio::sync::oneshot::channel();
        let flushing = tokio::spawn(async move {
            writer_store
                .flush_with_writer(|path, out, lease| async move {
                    captured_tx.send(()).unwrap();
                    release_rx.await.unwrap();
                    write_private_file_async(&path, out, lease).await
                })
                .await
        });
        captured_rx.await.unwrap();
        store
            .update(|snap| {
                snap.strategy_stats
                    .insert("during".into(), Default::default());
            })
            .await;
        release_tx.send(()).unwrap();
        flushing.await.unwrap().unwrap();
        assert!(
            store.is_dirty(),
            "newer update was not part of persisted snapshot"
        );
        let before = AsyncStateStore::load(path.clone())
            .await
            .unwrap()
            .snapshot()
            .await;
        assert!(before.strategy_stats.contains_key("before"));
        assert!(!before.strategy_stats.contains_key("during"));
        store.flush().await.unwrap();
        assert!(!store.is_dirty());
        let after = AsyncStateStore::load(path).await.unwrap().snapshot().await;
        assert!(after.strategy_stats.contains_key("during"));
    }

    #[tokio::test]
    async fn concurrent_flushes_serialize_and_cancellation_keeps_dirty() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("state.json");
        let store = AsyncStateStore::load(path.clone()).await.unwrap();
        store.update(|_| {}).await;
        let writer_store = store.clone();
        let (captured_tx, captured_rx) = tokio::sync::oneshot::channel();
        let flushing = tokio::spawn(async move {
            writer_store
                .flush_with_writer(|_path, _out, lease| async move {
                    captured_tx.send(()).unwrap();
                    std::future::pending::<()>().await;
                    Ok(lease)
                })
                .await
        });
        captured_rx.await.unwrap();
        assert!(
            store.inner.flush_lock.try_lock().is_err(),
            "writer owns the lease across I/O"
        );
        flushing.abort();
        assert!(flushing.await.unwrap_err().is_cancelled());
        assert!(store.is_dirty());
        tokio::try_join!(store.flush(), store.flush()).unwrap();
        assert!(!store.is_dirty());
        AsyncStateStore::load(path).await.unwrap();
    }

    #[tokio::test]
    async fn write_failure_never_clears_dirty_snapshot() {
        let dir = TempDir::new().unwrap();
        let store = AsyncStateStore::load(dir.path().join("state.json"))
            .await
            .unwrap();
        store.update(|_| {}).await;
        let failed = store
            .flush_with_writer(|_path, _out, _lease| async {
                Err(AegisError::Io(std::io::Error::other(
                    "injected writer failure",
                )))
            })
            .await;
        assert!(failed.is_err());
        assert!(store.is_dirty());
        store.flush().await.unwrap();
        assert!(!store.is_dirty());
    }

    #[tokio::test]
    async fn async_store_create_and_flush() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("state.json");

        let store = AsyncStateStore::load(path.clone()).await.unwrap();
        assert!(!store.is_dirty());

        // Обновить в памяти
        store
            .update(|snap| {
                snap.strategy_stats.insert(
                    "test_key".into(),
                    super::super::schema::StrategyStatsV2::default(),
                );
            })
            .await;
        assert!(store.is_dirty());

        // Flush на диск
        store.flush().await.unwrap();
        assert!(!store.is_dirty());

        // Проверить что файл создан
        assert!(path.exists());

        // Загрузить заново и проверить
        let store2 = AsyncStateStore::load(path).await.unwrap();
        let snap = store2.snapshot().await;
        assert_eq!(snap.schema_version, 2);
        assert!(snap.strategy_stats.contains_key("test_key"));
    }

    #[tokio::test]
    async fn async_store_no_flush_when_clean() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("state.json");

        let store = AsyncStateStore::load(path.clone()).await.unwrap();
        // Flush без изменений — ничего не пишет
        store.flush().await.unwrap();
        assert!(!path.exists()); // файл не создан
    }

    #[tokio::test]
    async fn async_store_migrates_legacy_v1_json() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("state.json");
        let legacy = StateFile {
            entries: std::collections::HashMap::from([(
                "legacy-key".into(),
                std::collections::HashMap::from([(
                    "passthrough".into(),
                    StrategyStats {
                        success_rate: 0.8,
                        avg_handshake_ms: 42.0,
                        last_rst_source: Some("dpi".into()),
                        confidence: 0.6,
                    },
                )]),
            )]),
        };
        tokio::fs::write(&path, serde_json::to_vec(&legacy).unwrap())
            .await
            .unwrap();

        let store = AsyncStateStore::load(path).await.unwrap();
        let snap = store.snapshot().await;
        let stats = snap
            .strategy_stats
            .get("legacy-key|passthrough")
            .expect("migrated strategy stats");
        assert!(stats.trials >= 1);
        assert!(stats.successes >= 1);
        assert!(stats.fitness_score > 0.5);
    }

    #[tokio::test]
    async fn missing_master_key_quarantines_sealed_state_and_recovers() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("state.json");

        let store = AsyncStateStore::load(path.clone()).await.unwrap();
        store
            .update(|snap| {
                snap.strategy_stats.insert(
                    "learned-before-key-loss".into(),
                    super::super::schema::StrategyStatsV2::default(),
                );
            })
            .await;
        store.flush().await.unwrap();
        assert!(path.exists());

        let seed = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .find(|candidate| {
                candidate
                    .file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.starts_with('.') && name.ends_with(".seed"))
            })
            .expect("private state seed");
        std::fs::remove_file(seed).unwrap();

        let recovered = AsyncStateStore::load(path.clone()).await.unwrap();
        assert!(
            recovered.snapshot().await.strategy_stats.is_empty(),
            "unreadable learned state must not be silently treated as plaintext"
        );
        assert!(!path.exists(), "orphaned sealed state must move aside");
        let quarantined = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .find(|candidate| {
                candidate
                    .file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.contains("state.json.orphaned-key."))
            })
            .expect("quarantined state blob");
        assert_eq!(&std::fs::read(quarantined).unwrap()[..4], b"AEGS");

        recovered.update(|_| {}).await;
        recovered.flush().await.unwrap();
        assert!(path.exists(), "a new sealed state must be writable");
        AsyncStateStore::load(path).await.unwrap();
    }

    // Audit F4: the forensic-safe RAM-only store keeps updates in memory but
    // never writes them — flush() is a no-op, so no state.json activity trail
    // is left on a seizable disk.
    #[tokio::test]
    async fn ephemeral_store_keeps_ram_but_never_persists() {
        let store = AsyncStateStore::ephemeral();
        store.update(|_snap| {}).await;
        assert!(store.is_dirty(), "update should mark dirty in RAM");
        store.flush().await.unwrap();
        assert!(
            store.is_dirty(),
            "ephemeral flush must be a no-op (nothing persisted/cleared)"
        );
    }
}

#[cfg(test)]
#[path = "flush_preparation_tests.rs"]
mod flush_preparation_tests;

#[cfg(test)]
#[path = "load_preparation_tests.rs"]
mod load_preparation_tests;

#[cfg(test)]
#[path = "decrypt_preparation_tests.rs"]
mod decrypt_preparation_tests;
