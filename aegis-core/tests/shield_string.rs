//! String decrypt из env (без реальных секретов в репозитории).

use aegis_core::shield::string_crypt::decrypt_env_blob;
use std::sync::Mutex;

static ENV_LOCK: Mutex<()> = Mutex::new(());

#[test]
fn decrypt_env_blob_without_env_returns_none() {
    let _g = ENV_LOCK.lock().expect("lock");
    std::env::remove_var("AEGIS_STRING_KEY");
    std::env::remove_var("AEGIS_ENCRYPTED_BLOB");
    assert!(decrypt_env_blob().is_none());
}

#[test]
fn decrypt_env_blob_roundtrip() {
    let _g = ENV_LOCK.lock().expect("lock");
    std::env::set_var("AEGIS_STRING_KEY", "k");
    // "hello" xor 'k' per byte -> hex
    let raw: Vec<u8> = b"hello".iter().map(|b| b ^ b'k').collect();
    std::env::set_var("AEGIS_ENCRYPTED_BLOB", hex::encode(&raw));
    let out = decrypt_env_blob().expect("decrypt");
    assert_eq!(out, b"hello");
    std::env::remove_var("AEGIS_STRING_KEY");
    std::env::remove_var("AEGIS_ENCRYPTED_BLOB");
}
