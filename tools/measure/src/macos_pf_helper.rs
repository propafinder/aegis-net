use std::path::Path;

use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::artifact::read_json;

pub fn print_macos_pf_state_basename(state_base_dir: &str, home: Option<&str>, user: Option<&str>) {
    let mut hasher = Sha256::new();
    hasher.update(b"aegis-macos-pf-state-v2");
    hasher.update(state_base_dir.as_bytes());
    if let Some(home) = home.filter(|value| !value.is_empty()) {
        hasher.update(home.as_bytes());
    }
    if let Some(user) = user.filter(|value| !value.is_empty()) {
        hasher.update(user.as_bytes());
    }
    let digest = format!("{:x}", hasher.finalize());
    println!(".pf-state-{}.json", &digest[..12]);
}

pub fn print_macos_pf_state_json(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    if !path.exists() {
        println!("{{}}");
        return Ok(());
    }
    println!("{}", serde_json::to_string(&read_json(path)?)?);
    Ok(())
}

pub fn print_macos_pf_state_field(
    path: &Path,
    field: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    if !path.exists() {
        println!();
        return Ok(());
    }
    let payload = read_json(path)?;
    match payload.get(field).unwrap_or(&Value::Null) {
        Value::Bool(value) => println!("{}", if *value { "true" } else { "false" }),
        Value::Null => println!(),
        Value::String(value) => println!("{value}"),
        value => println!("{value}"),
    }
    Ok(())
}
