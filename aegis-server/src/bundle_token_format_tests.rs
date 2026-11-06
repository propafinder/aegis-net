use super::*;
use crate::bundle_tokens::test_tempdir;

#[test]
fn actual_malformed_store_entry_points_refuse_before_transaction_reload() {
    let tmp = test_tempdir();
    let path = tmp.path().join("tokens.json");
    let mut store = BundleTokenStore::load(&path).unwrap();
    std::fs::write(&path, b"invalid store fixture").unwrap();
    assert_eq!(
        store.authorize_read("short"),
        Err(BundleTokenError::NotFound)
    );
    assert_eq!(store.redeem("short"), Err(BundleTokenError::NotFound));
    assert_eq!(
        store.redeem_after_read("short", None),
        Err(BundleTokenError::NotFound)
    );
    let mut lock_name = path.as_os_str().to_os_string();
    lock_name.push(".lock");
    assert!(!std::path::PathBuf::from(lock_name).exists());
}

#[test]
fn actual_canonical_store_miss_keeps_fresh_locked_reload() {
    let tmp = test_tempdir();
    let path = tmp.path().join("tokens.json");
    let mut store = BundleTokenStore::load(&path).unwrap();
    std::fs::write(&path, b"invalid store fixture").unwrap();
    let canonical = "0".repeat(64);
    assert!(matches!(
        store.authorize_read(&canonical),
        Err(BundleTokenError::PersistFailed(_))
    ));
    assert!(matches!(
        store.redeem(&canonical),
        Err(BundleTokenError::PersistFailed(_))
    ));
    assert!(matches!(
        store.redeem_after_read(&canonical, None),
        Err(BundleTokenError::PersistFailed(_))
    ));
    let mut lock_name = path.as_os_str().to_os_string();
    lock_name.push(".lock");
    assert!(std::path::PathBuf::from(lock_name).is_file());
}
