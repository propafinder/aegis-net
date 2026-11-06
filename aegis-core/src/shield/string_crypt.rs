//! Расшифровка blob из env `AEGIS_ENCRYPTED_BLOB` (hex XOR с ключом `AEGIS_STRING_KEY`).

pub fn decrypt_env_blob() -> Option<Vec<u8>> {
    let key = std::env::var("AEGIS_STRING_KEY").ok()?;
    let hex_blob = std::env::var("AEGIS_ENCRYPTED_BLOB").ok()?;
    let data = hex::decode(hex_blob.trim()).ok()?;
    let kb = key.as_bytes();
    if kb.is_empty() {
        return None;
    }
    let out: Vec<u8> = data
        .iter()
        .enumerate()
        .map(|(i, b)| b ^ kb[i % kb.len()])
        .collect();
    Some(out)
}
