use std::{fs, path::PathBuf};

use serde_json::{json, Value};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        Some("refresh-dry-run") => {
            let knowledge = aegis_knowledge::Knowledge::load_embedded()?;
            let payload = json!({
                "event": "knowledge_refresh_dry_run",
                "manifest_version": knowledge.manifest.version,
                "file_count": knowledge.manifest.files.len(),
                "changed": false,
            });
            println!("{}", serde_json::to_string(&payload)?);
        }
        Some("validate-refresh-dry-run") => {
            let input = next_path(&mut args, "--input")?;
            let payload: Value = serde_json::from_str(&fs::read_to_string(input)?)?;
            ensure(
                payload["event"].as_str() == Some("knowledge_refresh_dry_run"),
                "unexpected refresh event",
            )?;
            ensure(
                payload["changed"].as_bool() == Some(false),
                "dry-run must not report changes",
            )?;
            ensure(
                payload["file_count"].as_u64().unwrap_or(0) >= 5,
                "manifest file count below expected corpus floor",
            )?;
        }
        Some("export-ja3-targets") => {
            let output = next_path(&mut args, "--output")?;
            let knowledge = aegis_knowledge::Knowledge::load_embedded()?;
            let mut targets = knowledge.browser_corpus.fingerprints.clone();
            targets.sort_by(|a, b| {
                a.target_class
                    .cmp(&b.target_class)
                    .then_with(|| b.weight.total_cmp(&a.weight))
                    .then_with(|| a.id.cmp(&b.id))
            });
            let payload = json!({
                "event": "phase_b_ja3_profile_targets",
                "schema_version": 1,
                "corpus_version": knowledge.browser_corpus.version,
                "targets": targets,
            });
            write_json(&output, &payload)?;
        }
        Some("validate-ja3-targets") => {
            let input = next_path(&mut args, "--input")?;
            let payload: Value = serde_json::from_str(&fs::read_to_string(input)?)?;
            ensure(
                payload["event"].as_str() == Some("phase_b_ja3_profile_targets"),
                "unexpected JA3 target event",
            )?;
            let targets = payload["targets"].as_array().ok_or("missing targets")?;
            ensure(!targets.is_empty(), "empty JA3 targets")?;
            ensure(
                targets.iter().any(|target| {
                    target["target_class"].as_str() == Some("https_ws")
                        && target["alpn"].as_array().is_some_and(|alpn| {
                            alpn.iter().any(|value| value.as_str() == Some("h2"))
                        })
                }),
                "missing https_ws h2 JA3 target",
            )?;
            ensure(
                targets
                    .iter()
                    .any(|target| target["target_class"].as_str() == Some("masque_derived")),
                "missing masque_derived JA3 target",
            )?;
            for class in ["legacy_tls", "https_ws", "masque_derived"] {
                ensure(
                    targets
                        .iter()
                        .any(|target| target["target_class"].as_str() == Some(class)),
                    &format!("missing primary JA3 target class: {class}"),
                )?;
            }
            for target in targets {
                let class = target["target_class"]
                    .as_str()
                    .ok_or("JA3 target missing target_class")?;
                let alpn = target["alpn"].as_array().ok_or("JA3 target missing alpn")?;
                let expected = runtime_alpn_for_target_class(class);
                ensure(
                    !expected.is_empty(),
                    &format!("unknown runtime ALPN target class: {class}"),
                )?;
                ensure(
                    alpn.iter().all(|value| {
                        value
                            .as_str()
                            .is_some_and(|value| expected.contains(&value))
                    }),
                    &format!("JA3 target ALPN is outside runtime mapping: {class}"),
                )?;
                ensure(
                    expected
                        .iter()
                        .any(|expected| alpn.iter().any(|value| value.as_str() == Some(*expected))),
                    &format!("JA3 target ALPN does not overlap runtime mapping: {class}"),
                )?;
            }
        }
        _ => {
            eprintln!(
                "usage:\n  aegis-knowledge refresh-dry-run\n  aegis-knowledge validate-refresh-dry-run --input PATH\n  aegis-knowledge export-ja3-targets --output PATH\n  aegis-knowledge validate-ja3-targets --input PATH"
            );
            std::process::exit(2);
        }
    }
    Ok(())
}

fn next_path(
    args: &mut impl Iterator<Item = String>,
    expected_flag: &str,
) -> Result<PathBuf, Box<dyn std::error::Error>> {
    match (args.next(), args.next()) {
        (Some(flag), Some(value)) if flag == expected_flag => Ok(PathBuf::from(value)),
        _ => Err(format!("missing {expected_flag} PATH").into()),
    }
}

fn ensure(condition: bool, message: &str) -> Result<(), Box<dyn std::error::Error>> {
    if condition {
        Ok(())
    } else {
        Err(message.into())
    }
}

fn write_json(path: &PathBuf, value: &Value) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, serde_json::to_string_pretty(value)? + "\n")?;
    Ok(())
}

fn runtime_alpn_for_target_class(target_class: &str) -> &'static [&'static str] {
    match target_class {
        "legacy_tls" => &["http/1.1"],
        "https_ws" => &["h2", "http/1.1"],
        "grpc_stream" => &["h2"],
        "masque_derived" => &["h3", "masque"],
        _ => &[],
    }
}
