//! Fixed paired research-tool metadata. Metadata names unsigned build bytes;
//! signing must separately attest those bytes to the final signed executables.
use super::{hash, invalid, verify_pe, PeMachine, WinctlError};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub(super) const EXES: [&str; 4] = [
    "aegis-client.exe",
    "aegis-winctl.exe",
    "aegis-measure.exe",
    "aegis-transport-lab.exe",
];
pub(super) const LEAF: &str = "research-operators.json";
const MEASURE_CAPS: [&str; 7] = [
    "private-control",
    "poisson-control",
    "poisson-insertion",
    "privacy-pcap-export",
    "privacy-study-assemble",
    "privacy-frontier",
    "brain-outcome-replay",
];
const LAB_CAPS: [&str; 6] = [
    "dependencies",
    "topology",
    "awgn",
    "poisson-channel",
    "privacy-channel",
    "bittraps-channel",
];

#[derive(Serialize, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub(super) struct ToolInfo {
    schema: String,
    tool: String,
    crate_version: String,
    source_commit: String,
    cargo_lock_sha256: String,
    target_triple: String,
    build_features: String,
    rustc_version: String,
    binary_sha256: String,
    capabilities: Vec<String>,
}
#[derive(Serialize, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub(super) struct Pair {
    schema: String,
    measure: ToolInfo,
    transport_lab: ToolInfo,
}
fn hex(s: &str, n: usize) -> bool {
    s.len() == n
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
pub(super) fn validate(
    raw: &[u8],
    files: &BTreeMap<String, Vec<u8>>,
    source: &str,
    lock: &str,
    rustc: &str,
    signed: bool,
) -> Result<(), WinctlError> {
    if raw.len() > 16384
        || !hex(source, 40)
        || !hex(lock, 64)
        || rustc.len() > 512
        || !rustc.starts_with("rustc ")
        || !rustc.bytes().all(|c| c.is_ascii_graphic() || c == b' ')
    {
        return Err(invalid());
    }
    let pair: Pair = serde_json::from_slice(raw).map_err(|_| invalid())?;
    if pair.schema != "aegis_windows_research_operators_v1" {
        return Err(invalid());
    }
    for (info, name, tool, version, caps) in [
        (
            &pair.measure,
            "aegis-measure.exe",
            "aegis-measure",
            "0.3.12",
            MEASURE_CAPS.as_slice(),
        ),
        (
            &pair.transport_lab,
            "aegis-transport-lab.exe",
            "aegis-transport-lab",
            "0.1.0",
            LAB_CAPS.as_slice(),
        ),
    ] {
        if info.schema != "aegis_research_tool_build_info_v1"
            || info.tool != tool
            || info.crate_version != version
            || info.source_commit != source
            || info.cargo_lock_sha256 != lock
            || info.target_triple != "x86_64-pc-windows-msvc"
            || info.build_features != "none"
            || info.rustc_version != rustc
            || !hex(&info.binary_sha256, 64)
            || info
                .capabilities
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>()
                != caps
        {
            return Err(invalid());
        }
        let bytes = files.get(name).ok_or_else(invalid)?;
        verify_pe(bytes, PeMachine::X64)?;
        // Signed PE bytes intentionally differ; the finalizer's independently
        // pinned provider-attestation verifier binds the original unsigned hash.
        if !signed && hash(bytes) != info.binary_sha256 {
            return Err(invalid());
        }
    }
    Ok(())
}
pub(super) fn validate_for_build(
    raw: &[u8],
    files: &BTreeMap<String, Vec<u8>>,
    source: &str,
    signed: bool,
) -> Result<(), WinctlError> {
    validate(
        raw,
        files,
        source,
        option_env!("AEGIS_CARGO_LOCK_SHA256").ok_or_else(invalid)?,
        option_env!("AEGIS_RESEARCH_RUSTC_VERSION").ok_or_else(invalid)?,
        signed,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> (Pair, BTreeMap<String, Vec<u8>>, String, String, String) {
        let source = "a".repeat(40);
        let lock = "b".repeat(64);
        let rustc = "rustc 1.97.0 (synthetic 2026-01-01)".to_owned();
        let mut pe = vec![0; 70];
        pe[..2].copy_from_slice(b"MZ");
        pe[60..64].copy_from_slice(&64u32.to_le_bytes());
        pe[64..].copy_from_slice(b"PE\0\0\x64\x86");
        let mut files = BTreeMap::new();
        files.insert("aegis-measure.exe".into(), pe.clone());
        files.insert("aegis-transport-lab.exe".into(), pe.clone());
        let make = |tool: &str, version: &str, caps: &[&str]| ToolInfo {
            schema: "aegis_research_tool_build_info_v1".into(),
            tool: tool.into(),
            crate_version: version.into(),
            source_commit: source.clone(),
            cargo_lock_sha256: lock.clone(),
            target_triple: "x86_64-pc-windows-msvc".into(),
            build_features: "none".into(),
            rustc_version: rustc.clone(),
            binary_sha256: hash(&pe),
            capabilities: caps.iter().map(|x| (*x).into()).collect(),
        };
        (
            Pair {
                schema: "aegis_windows_research_operators_v1".into(),
                measure: make("aegis-measure", "0.3.12", &MEASURE_CAPS),
                transport_lab: make("aegis-transport-lab", "0.1.0", &LAB_CAPS),
            },
            files,
            source,
            lock,
            rustc,
        )
    }
    #[test]
    fn exact_unsigned_pair_admitted_and_missing_half_refused() {
        let (p, mut f, s, l, r) = fixture();
        let b = serde_json::to_vec(&p).unwrap();
        validate(&b, &f, &s, &l, &r, false).unwrap();
        f.remove("aegis-transport-lab.exe");
        assert!(validate(&b, &f, &s, &l, &r, false).is_err());
    }
    #[test]
    fn identity_features_versions_caps_and_unsigned_hash_cannot_be_substituted() {
        let (p, f, s, l, r) = fixture();
        for n in 0..8 {
            let mut q = p.clone();
            match n {
                0 => q.measure.source_commit = "c".repeat(40),
                1 => q.measure.cargo_lock_sha256 = "c".repeat(64),
                2 => q.measure.target_triple = "aarch64-pc-windows-msvc".into(),
                3 => q.measure.rustc_version.push('x'),
                4 => q.measure.build_features = "experimental".into(),
                5 => q.measure.crate_version = "0.3.13".into(),
                6 => q.measure.capabilities.reverse(),
                _ => q.measure.binary_sha256 = "c".repeat(64),
            }
            assert!(validate(&serde_json::to_vec(&q).unwrap(), &f, &s, &l, &r, false).is_err());
        }
    }
    #[test]
    fn duplicate_unknown_and_oversized_metadata_refuse() {
        let (p, f, s, l, r) = fixture();
        let b = serde_json::to_vec(&p).unwrap();
        for key in ["schema", "unknown"] {
            let mut bad = format!("{{\"{key}\":\"x\",").into_bytes();
            bad.extend_from_slice(&b[1..]);
            assert!(validate(&bad, &f, &s, &l, &r, false).is_err());
        }
        assert!(validate(&vec![b' '; 16385], &f, &s, &l, &r, false).is_err());
    }
    #[test]
    fn signed_metadata_retains_unsigned_identity_not_a_signature_claim() {
        let (p, mut f, s, l, r) = fixture();
        f.get_mut("aegis-measure.exe").unwrap().push(1);
        let b = serde_json::to_vec(&p).unwrap();
        assert!(validate(&b, &f, &s, &l, &r, false).is_err());
        validate(&b, &f, &s, &l, &r, true).unwrap();
        // This admission alone never establishes WinVerifyTrust/attestation.
    }
}
