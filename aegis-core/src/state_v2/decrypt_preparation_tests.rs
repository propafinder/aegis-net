//! Actual decrypt-entry placement regressions; synthetic PrivateFile inputs only.
//! No timing assertion, native provider, injected delay or OS-lock wait claim.
use super::*;
use std::sync::Mutex;
use std::thread::ThreadId;
use tempfile::TempDir;

struct ObservedInput {
    bytes: Vec<u8>,
    observed: Arc<Mutex<Vec<ThreadId>>>,
}
impl AsRef<[u8]> for ObservedInput {
    fn as_ref(&self) -> &[u8] {
        self.observed
            .lock()
            .unwrap()
            .push(std::thread::current().id());
        &self.bytes
    }
}
fn synthetic_snapshot_bytes() -> Vec<u8> {
    let mut snapshot = StateSnapshot::default();
    snapshot
        .strategy_stats
        .insert("synthetic-private-load|fixture".into(), Default::default());
    serde_json::to_vec(&snapshot).unwrap()
}
fn private_fixture() -> (TempDir, PathBuf) {
    // Refuse an override before any key operation; never use or render its value.
    assert!(
        std::env::var_os("AEGIS_STATE_KEY").is_none(),
        "run isolated with state-key override unset"
    );
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("synthetic-state.json");
    assert_eq!(
        crate::state_secret::key_store_status(&path)
            .unwrap()
            .backend,
        crate::state_secret::StateKeyStore::PrivateFile
    );
    (dir, path)
}
async fn observe(
    path: PathBuf,
    bytes: Vec<u8>,
) -> (
    ObservedInput,
    Result<Option<Vec<u8>>, AegisError>,
    Vec<ThreadId>,
) {
    let observed = Arc::new(Mutex::new(Vec::new()));
    let (input, result) = prepare_loaded_decryption(
        path,
        ObservedInput {
            bytes,
            observed: observed.clone(),
        },
    )
    .await
    .unwrap();
    let records = observed.lock().unwrap().clone();
    (input, result, records)
}
#[tokio::test(flavor = "current_thread")]
async fn plaintext_decrypt_entry_leaves_current_runtime_thread() {
    let (_dir, path) = private_fixture();
    let caller = std::thread::current().id();
    let bytes = synthetic_snapshot_bytes();
    let original = bytes.clone();
    let (input, result, observed) = observe(path.clone(), bytes).await;
    assert!(result.unwrap().is_none());
    assert_eq!(input.bytes, original, "plaintext owned bytes are preserved");
    let prepared = prepare_loaded_snapshot(input.bytes).await.unwrap();
    assert!(prepared
        .snapshot
        .strategy_stats
        .contains_key("synthetic-private-load|fixture"));
    assert!(
        !path.exists(),
        "plaintext preparation does not create state"
    );
    assert_eq!(observed.len(), 1, "one actual crypto-entry borrow");
    assert_ne!(
        observed[0], caller,
        "decryption preparation must leave the single async thread"
    );
}
#[tokio::test(flavor = "current_thread")]
async fn private_file_aead_decrypt_entry_leaves_current_runtime_thread() {
    let (_dir, path) = private_fixture();
    let caller = std::thread::current().id();
    let plaintext = synthetic_snapshot_bytes();
    let sealed = seal_state_blob(&path, &plaintext).unwrap();
    crate::state_secret::write_private_file(&path, &sealed).unwrap();
    let (input, result, observed) = observe(path.clone(), sealed.clone()).await;
    assert_eq!(input.bytes, sealed, "owned sealed bytes remain exact");
    let reopened = result.unwrap().expect("actual PrivateFile AEAD decrypt");
    assert_eq!(reopened, plaintext);
    let prepared = prepare_loaded_snapshot(reopened).await.unwrap();
    assert!(prepared
        .snapshot
        .strategy_stats
        .contains_key("synthetic-private-load|fixture"));
    assert_eq!(
        std::fs::read(&path).unwrap(),
        sealed,
        "preparation does not mutate source blob"
    );
    assert_eq!(observed.len(), 1, "one actual crypto-entry borrow");
    assert_ne!(
        observed[0], caller,
        "key lookup and AEAD entry must leave the single async thread"
    );
}
#[tokio::test(flavor = "current_thread")]
async fn tampered_private_file_crypto_error_preserves_exact_blob_without_quarantine() {
    let (dir, path) = private_fixture();
    let mut sealed = seal_state_blob(&path, &synthetic_snapshot_bytes()).unwrap();
    *sealed.last_mut().unwrap() ^= 1;
    crate::state_secret::write_private_file(&path, &sealed).unwrap();
    let expected = maybe_decrypt_state_blob(&path, &sealed)
        .unwrap_err()
        .to_string();
    let (input, result, _) = observe(path.clone(), sealed.clone()).await;
    assert_eq!(input.bytes, sealed);
    assert_eq!(result.unwrap_err().to_string(), expected);
    assert!(
        AsyncStateStore::load(path.clone()).await.is_err(),
        "crypto corruption remains fatal"
    );
    assert_eq!(std::fs::read(&path).unwrap(), sealed);
    assert!(!std::fs::read_dir(dir.path()).unwrap().any(|entry| entry
        .unwrap()
        .file_name()
        .to_string_lossy()
        .contains("orphaned-key")));
}
