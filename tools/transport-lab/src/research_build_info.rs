//! Content-free producer snapshot; archive signatures authenticate delivery.
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io::{self, Read},
};
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BuildInfo {
    pub schema: String,
    pub tool: String,
    pub crate_version: String,
    pub source_commit: String,
    pub cargo_lock_sha256: String,
    pub target_triple: String,
    pub build_features: String,
    pub rustc_version: String,
    pub binary_sha256: String,
    pub capabilities: Vec<String>,
}
pub const MEASURE_CAPABILITIES: &[&str] = &[
    "private-control",
    "poisson-control",
    "poisson-insertion",
    "privacy-pcap-export",
    "privacy-study-assemble",
    "privacy-frontier",
    "brain-outcome-replay",
];
pub const LAB_CAPABILITIES: &[&str] = &[
    "dependencies",
    "topology",
    "awgn",
    "poisson-channel",
    "privacy-channel",
    "bittraps-channel",
];
pub fn emit(tool: &str, capabilities: &[&str]) -> Result<(), Box<dyn std::error::Error>> {
    let expected = match tool {
        "aegis-measure" => MEASURE_CAPABILITIES,
        "aegis-transport-lab" => LAB_CAPABILITIES,
        _ => return Err(io::Error::other("research role refused").into()),
    };
    if capabilities != expected {
        return Err(io::Error::other("research capabilities refused").into());
    }
    let mut binary = Vec::new();
    File::open(std::env::current_exe()?)?
        .take(512 * 1024 * 1024 + 1)
        .read_to_end(&mut binary)?;
    if binary.is_empty() || binary.len() > 512 * 1024 * 1024 {
        return Err(io::Error::other("research executable size refused").into());
    }
    let info = BuildInfo {
        schema: "aegis_research_tool_build_info_v1".into(),
        tool: tool.into(),
        crate_version: env!("CARGO_PKG_VERSION").into(),
        source_commit: env!("AEGIS_RESEARCH_SOURCE_COMMIT").into(),
        cargo_lock_sha256: env!("AEGIS_RESEARCH_LOCK_SHA256").into(),
        target_triple: env!("AEGIS_RESEARCH_TARGET").into(),
        build_features: env!("AEGIS_RESEARCH_FEATURES").into(),
        rustc_version: env!("AEGIS_RESEARCH_RUSTC").into(),
        binary_sha256: format!("{:x}", Sha256::digest(&binary)),
        capabilities: capabilities.iter().map(|s| (*s).into()).collect(),
    };
    println!("{}", serde_json::to_string(&info)?);
    Ok(())
}
