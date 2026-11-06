use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    process::Command as ProcessCommand,
    time::Instant,
};

use serde::Deserialize;
use serde_json::{json, Value};

mod contract;
mod execution;

pub use contract::adversarial_runner_contract_check;
use execution::{excerpt, run_live_command, trim_output};

#[derive(Debug, Deserialize)]
struct ExpectedToml {
    thresholds: BTreeMap<String, f64>,
}

#[derive(Debug, Deserialize)]
struct ScenarioToml {
    name: String,
    transport: String,
    #[allow(dead_code)]
    description: Option<String>,
    expected_threshold_key: Option<String>,
}

#[derive(Debug)]
struct Scenario {
    name: String,
    transport: String,
    expected_threshold_key: String,
    path: PathBuf,
}

pub fn adversarial_runner(
    scenario: Option<&str>,
    network_profile: Option<&str>,
    dry_run: bool,
    live_command: Option<&str>,
    live_matrix: bool,
    timeout_seconds: f64,
) -> Result<Vec<Value>, Box<dyn std::error::Error>> {
    if dry_run && live_command.is_some() {
        return Err("--dry-run conflicts with --live-command".into());
    }
    if dry_run && live_matrix {
        return Err("--dry-run conflicts with --live-matrix".into());
    }
    if live_matrix && live_command.is_none() {
        return Err("--live-matrix requires --live-command".into());
    }
    if !dry_run && live_command.is_none() {
        return Err(
            "use --dry-run or provide --live-command for bounded measured execution".into(),
        );
    }
    if live_command.is_some() && !live_matrix && (scenario.is_none() || network_profile.is_none()) {
        return Err(
            "--live-command requires --scenario and --network-profile unless --live-matrix is set"
                .into(),
        );
    }

    let root = std::env::current_dir()?.join("tests/adversarial");
    let scenarios = scenario_paths(&root, scenario)?
        .into_iter()
        .map(load_scenario)
        .collect::<Result<Vec<_>, _>>()?;
    let profiles = profile_paths(&root, network_profile)?;
    if dry_run {
        dry_run_events(&root, &scenarios, &profiles)
    } else {
        measured_events(
            &root,
            &scenarios,
            &profiles,
            live_command.unwrap_or_default(),
            timeout_seconds,
        )
    }
}

fn load_expected(root: &Path) -> Result<BTreeMap<String, f64>, Box<dyn std::error::Error>> {
    let expected: ExpectedToml = toml::from_str(&fs::read_to_string(root.join("expected.toml"))?)?;
    Ok(expected.thresholds)
}

fn load_scenario(path: PathBuf) -> Result<Scenario, Box<dyn std::error::Error>> {
    let parsed: ScenarioToml = toml::from_str(&fs::read_to_string(&path)?)?;
    Ok(Scenario {
        expected_threshold_key: parsed
            .expected_threshold_key
            .unwrap_or_else(|| parsed.transport.clone()),
        name: parsed.name,
        transport: parsed.transport,
        path,
    })
}

fn scenario_paths(
    root: &Path,
    selected: Option<&str>,
) -> Result<Vec<PathBuf>, Box<dyn std::error::Error>> {
    let dir = root.join("scenarios");
    if let Some(selected) = selected {
        let path = dir.join(format!("{selected}.toml"));
        if !path.is_file() {
            return Err(format!("unknown scenario: {selected}").into());
        }
        return Ok(vec![path]);
    }
    sorted_files(&dir, "toml")
}

fn profile_paths(
    root: &Path,
    selected: Option<&str>,
) -> Result<Vec<PathBuf>, Box<dyn std::error::Error>> {
    let dir = root.join("network-profiles");
    if let Some(selected) = selected {
        let mut path = dir.join(selected);
        if path.extension().is_none() {
            path.set_extension("sh");
        }
        if !path.is_file() {
            return Err(format!("unknown network profile: {selected}").into());
        }
        return Ok(vec![path]);
    }
    sorted_files(&dir, "sh")
}

fn sorted_files(dir: &Path, extension: &str) -> Result<Vec<PathBuf>, Box<dyn std::error::Error>> {
    let mut files = fs::read_dir(dir)?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.extension().and_then(|value| value.to_str()) == Some(extension))
        .collect::<Vec<_>>();
    files.sort();
    Ok(files)
}

fn dry_run_events(
    root: &Path,
    scenarios: &[Scenario],
    profiles: &[PathBuf],
) -> Result<Vec<Value>, Box<dyn std::error::Error>> {
    let thresholds = load_expected(root)?;
    let mut events = Vec::new();
    for scenario in scenarios {
        let threshold = scenario_threshold(&thresholds, scenario)?;
        for profile in profiles {
            events.push(json!({
                "event": "adversarial_scenario_planned",
                "schema_version": 1,
                "mode": "dry_run",
                "scenario": scenario.name,
                "transport": scenario.transport,
                "network_profile": profile_stem(profile),
                "threshold": threshold,
                "status": "PLANNED",
                "scenario_path": relative_to(root, &scenario.path),
                "profile_path": relative_to(root, profile),
            }));
        }
    }
    Ok(events)
}

fn measured_events(
    root: &Path,
    scenarios: &[Scenario],
    profiles: &[PathBuf],
    live_command: &str,
    timeout_seconds: f64,
) -> Result<Vec<Value>, Box<dyn std::error::Error>> {
    let thresholds = load_expected(root)?;
    if live_command.trim().is_empty() {
        return Err("--live-command must not be empty".into());
    }
    let mut events = Vec::new();
    for scenario in scenarios {
        let threshold = scenario_threshold(&thresholds, scenario)?;
        for profile in profiles {
            let profile_result = ProcessCommand::new(profile)
                .current_dir(root)
                .output()
                .map_err(|err| format!("failed to run profile {}: {err}", profile.display()))?;
            let started = Instant::now();
            let result = run_live_command(root, live_command, timeout_seconds);
            let duration_ms = started.elapsed().as_millis() as u64;
            let (status, reason) = if !profile_result.status.success() {
                ("FAIL", "network-profile-command-failed")
            } else if result.timed_out {
                ("TIMEOUT", "probe-command-timeout")
            } else if result.returncode == Some(0) {
                ("PASS", "probe-command-succeeded")
            } else {
                ("FAIL", "probe-command-failed")
            };
            events.push(json!({
                "event": "adversarial_scenario_measured",
                "schema_version": 1,
                "mode": "live_command",
                "scenario": scenario.name,
                "transport": scenario.transport,
                "network_profile": profile_stem(profile),
                "threshold": threshold,
                "status": status,
                "reason": reason,
                "duration_ms": duration_ms,
                "returncode": result.returncode,
                "profile_stdout": trim_output(&profile_result.stdout),
                "profile_stderr": trim_output(&profile_result.stderr),
                "stdout_excerpt": excerpt(&result.stdout),
                "stderr_excerpt": excerpt(&result.stderr),
                "scenario_path": relative_to(root, &scenario.path),
                "profile_path": relative_to(root, profile),
            }));
        }
    }
    Ok(events)
}

fn scenario_threshold(
    thresholds: &BTreeMap<String, f64>,
    scenario: &Scenario,
) -> Result<f64, Box<dyn std::error::Error>> {
    thresholds
        .get(&scenario.expected_threshold_key)
        .copied()
        .ok_or_else(|| {
            format!(
                "missing threshold for scenario {}: {}",
                scenario.name, scenario.expected_threshold_key
            )
            .into()
        })
}

fn profile_stem(path: &Path) -> String {
    path.file_stem()
        .and_then(|value| value.to_str())
        .unwrap_or_default()
        .to_string()
}

fn relative_to(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .into_owned()
}
