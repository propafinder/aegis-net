use std::{fs, path::Path};

use serde_json::Value;

pub fn read_json(path: &Path) -> Result<Value, Box<dyn std::error::Error>> {
    Ok(serde_json::from_str(&fs::read_to_string(path)?)?)
}

pub fn read_jsonl(path: &Path) -> Result<Vec<Value>, Box<dyn std::error::Error>> {
    let mut records = Vec::new();
    for (index, line) in fs::read_to_string(path)?.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        records.push(
            serde_json::from_str::<Value>(line)
                .map_err(|err| format!("{}:{} invalid JSONL: {err}", path.display(), index + 1))?,
        );
    }
    Ok(records)
}

pub fn read_optional_jsonl(path: Option<&Path>) -> Result<Vec<Value>, Box<dyn std::error::Error>> {
    match path {
        Some(path) => read_jsonl(path),
        None => Ok(Vec::new()),
    }
}

pub fn read_optional_json_path(
    path: Option<&Path>,
) -> Result<Option<Value>, Box<dyn std::error::Error>> {
    match path {
        Some(path) => read_json(path).map(Some),
        None => Ok(None),
    }
}

pub fn write_json(path: &Path, value: &Value) -> Result<(), Box<dyn std::error::Error>> {
    write_text(path, &(serde_json::to_string_pretty(value)? + "\n"))
}

pub fn print_pretty_json(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    println!("{}", serde_json::to_string_pretty(&read_json(path)?)?);
    Ok(())
}

pub fn write_text(path: &Path, text: &str) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, text)?;
    Ok(())
}
