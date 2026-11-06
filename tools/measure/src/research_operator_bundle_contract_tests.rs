//! Build-side synthetic ELF/input custody fixture, never executes a candidate.
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{fs, path::Path};
pub(crate) const SOURCE: &str = "172ad0d21d6e10c8dedf350089b665ed58025822";
pub(crate) fn fixture() -> tempfile::TempDir {
    let root = tempfile::tempdir().unwrap();
    fs::create_dir(root.path().join("bin")).unwrap();
    fs::create_dir(root.path().join("research")).unwrap();
    fs::write(root.path().join("Cargo.lock"), b"fixture-lock").unwrap();
    fs::write(root.path().join("bin/aegis-client"), b"fixture-client").unwrap();
    fs::write(root.path().join("bin/aegis-server"), b"fixture-server").unwrap();
    let lock = format!("{:x}", Sha256::digest(b"fixture-lock"));
    let roles = [
        (
            "aegis-measure",
            env!("CARGO_PKG_VERSION"),
            vec![
                "private-control",
                "poisson-control",
                "poisson-insertion",
                "privacy-pcap-export",
                "privacy-study-assemble",
                "privacy-frontier",
                "brain-outcome-replay",
            ],
        ),
        (
            "aegis-transport-lab",
            "0.1.0",
            vec![
                "dependencies",
                "topology",
                "awgn",
                "poisson-channel",
                "privacy-channel",
                "bittraps-channel",
            ],
        ),
    ];
    for (name, version, caps) in roles {
        let mut elf = vec![0u8; 64];
        elf[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
        elf[16..18].copy_from_slice(&2u16.to_le_bytes());
        elf[18..20].copy_from_slice(&62u16.to_le_bytes());
        elf[20..24].copy_from_slice(&1u32.to_le_bytes());
        elf[52..54].copy_from_slice(&64u16.to_le_bytes());
        fs::write(root.path().join(format!("bin/{name}")), &elf).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(
                root.path().join(format!("bin/{name}")),
                fs::Permissions::from_mode(0o700),
            )
            .unwrap();
        }
        fs::write(root.path().join(format!("research/{name}.build-info.json")), serde_json::to_vec(&json!({
            "schema":"aegis_research_tool_build_info_v1","tool":name,"crate_version":version,
            "source_commit":SOURCE,"cargo_lock_sha256":lock,"target_triple":"x86_64-unknown-linux-gnu",
            "build_features":"none","rustc_version":"rustc 1.97.1 (fixture)",
            "binary_sha256":format!("{:x}", Sha256::digest(&elf)),"capabilities":caps,
        })).unwrap()).unwrap();
    }
    let repository = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    for name in include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../packaging/research-operator-guides.txt"
    ))
    .lines()
    {
        fs::write(
            root.path().join("research").join(name),
            fs::read(repository.join("docs/research").join(name)).unwrap(),
        )
        .unwrap();
    }
    fs::copy(
        root.path().join("research/private-operator-delivery.md"),
        root.path().join("research/README.md"),
    )
    .unwrap();
    fs::write(
        root.path().join("research/THIRD-PARTY-NOTICES.txt"),
        b"fixture notices, not a real candidate or license proof",
    )
    .unwrap();
    root
}
pub(crate) fn build(root: &Path) -> Result<(), Box<dyn std::error::Error>> {
    crate::release_artifacts::build_release_bundle_manifest(
        root,
        "0.3.50",
        "x86_64",
        "x86_64-unknown-linux-gnu",
        SOURCE,
        "fixture-time",
    )
}
#[test]
fn private_research_pair_manifest_contains_actual_leaf_hashes_and_capabilities() {
    let root = fixture();
    build(root.path()).unwrap();
    let manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(root.path().join("bundle.manifest.json")).unwrap())
            .unwrap();
    for role in ["aegis-measure", "aegis-transport-lab"] {
        let bytes = fs::read(root.path().join(format!("bin/{role}"))).unwrap();
        assert_eq!(
            manifest["binaries"][role]["sha256"],
            format!("{:x}", Sha256::digest(&bytes)),
            "existing factory omits a real private operator leaf"
        );
        assert!(manifest["contains_prebuilt_binaries"]
            .as_array()
            .unwrap()
            .contains(&json!(format!("bin/{role}"))));
    }
    assert_eq!(
        manifest["research_operators"]["tools"][0]["capabilities"][1],
        "poisson-control"
    );
    assert_eq!(
        manifest["research_operators"]["tools"][1]["capabilities"][2],
        "awgn"
    );
    assert_eq!(
        manifest["research_operators"]["installed_fullwide_owner"],
        false
    );
}
