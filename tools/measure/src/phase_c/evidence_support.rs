use std::{fs, path::Path, process::Command as ProcessCommand};

pub(super) fn read_bundle_sha256_value(path: &Path) -> String {
    let Ok(text) = fs::read_to_string(path) else {
        return String::new();
    };
    text.split_whitespace().next().unwrap_or("").to_string()
}

pub(super) fn list_tar_gz_entries(path: &Path) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    if !path.is_file() {
        return Ok(Vec::new());
    }
    let output = ProcessCommand::new("tar").arg("-tzf").arg(path).output()?;
    if !output.status.success() {
        return Ok(Vec::new());
    }
    Ok(String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(str::to_string)
        .collect())
}
