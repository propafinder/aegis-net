//! Synthetic byte/descriptor admission controls; never executable identity proof.
use super::*;
use crate::research_operator_bundle_contract_tests::{fixture, SOURCE};
use std::os::unix::fs::PermissionsExt;

fn research_fixture() -> tempfile::TempDir {
    let root = fixture();
    for name in ["Cargo.lock", "bin/aegis-server", "bin/aegis-client"] {
        fs::remove_file(root.path().join(name)).unwrap();
    }
    root
}
fn inputs(root: &Path) -> Inputs<'_> {
    // Digest of the unchanged synthetic fixture's exact b"fixture-lock" bytes.
    Inputs {
        directory: root,
        version: "0.3.50",
        source: SOURCE,
        lock: "2661ec3f429d3d0a8df5e7e701325043dc1c161aa5cd32f420e51ff05ece3874",
        arch: "x86_64",
        target: "x86_64-unknown-linux-gnu",
    }
}
#[test]
fn exact_required_tree_builds_and_verifies_without_overwriting() {
    let root = research_fixture();
    let input = inputs(root.path());
    build(&input).unwrap();
    let first = read(&root.path().join(MANIFEST), 65536, false).unwrap();
    assert_eq!(verify(&input).unwrap(), hash(&first));
    assert!(build(&input).is_err());
    assert_eq!(
        read(&root.path().join(MANIFEST), 65536, false).unwrap(),
        first
    );
}
#[test]
fn extra_admin_and_helper_leaves_refuse_before_output() {
    for name in ["bin/aegis-measure-full", "helper.sh"] {
        let root = research_fixture();
        fs::write(root.path().join(name), b"inert administrative leaf").unwrap();
        assert!(build(&inputs(root.path())).is_err());
        assert!(!root.path().join(MANIFEST).exists());
        assert!(!root.path().join(SUMS).exists());
    }
}
#[test]
fn missing_pair_and_linked_research_member_refuse() {
    let root = research_fixture();
    fs::remove_file(root.path().join("bin/aegis-transport-lab")).unwrap();
    assert!(build(&inputs(root.path())).is_err());
    let root = research_fixture();
    let path = root.path().join("research/README.md");
    fs::remove_file(&path).unwrap();
    std::os::unix::fs::symlink("private-operator-delivery.md", path).unwrap();
    assert!(build(&inputs(root.path())).is_err());
}
#[test]
fn windows_pair_uses_exact_pe_names_without_relaxing_legacy_linux_admission() {
    let root = research_fixture();
    for name in ["aegis-measure", "aegis-transport-lab"] {
        let mut pe = vec![0u8; 70];
        pe[..2].copy_from_slice(b"MZ");
        pe[60..64].copy_from_slice(&64u32.to_le_bytes());
        pe[64..70].copy_from_slice(b"PE\0\0\x64\x86");
        fs::remove_file(root.path().join(format!("bin/{name}"))).unwrap();
        let binary = root.path().join(format!("bin/{name}.exe"));
        fs::write(&binary, &pe).unwrap();
        fs::set_permissions(&binary, fs::Permissions::from_mode(0o700)).unwrap();
        let capture = root.path().join(format!("research/{name}.build-info.json"));
        let mut value: Value = serde_json::from_slice(&fs::read(&capture).unwrap()).unwrap();
        value["target_triple"] = json!("x86_64-pc-windows-msvc");
        value["binary_sha256"] = json!(hash(&pe));
        fs::write(capture, serde_json::to_vec(&value).unwrap()).unwrap();
    }
    let mut input = inputs(root.path());
    input.target = "x86_64-pc-windows-msvc";
    build(&input).unwrap();
    verify(&input).unwrap();
    assert!(research_operator_delivery::admit(
        root.path(),
        SOURCE,
        input.lock,
        input.arch,
        input.target
    )
    .is_err());
}
#[test]
fn administrative_hash_is_required_and_research_material_is_forbidden() {
    let root = fixture();
    let binary = root.path().join("bin/aegis-measure");
    let expected = hash(&fs::read(&binary).unwrap());
    assert!(
        admit_administrative(root.path(), "x86_64", "x86_64-unknown-linux-gnu", &expected).is_err()
    );
    fs::remove_dir_all(root.path().join("research")).unwrap();
    fs::remove_file(root.path().join("bin/aegis-transport-lab")).unwrap();
    assert_eq!(
        admit_administrative(root.path(), "x86_64", "x86_64-unknown-linux-gnu", &expected).unwrap(),
        expected
    );
    assert!(admit_administrative(
        root.path(),
        "x86_64",
        "x86_64-unknown-linux-gnu",
        &"0".repeat(64)
    )
    .is_err());
}
#[test]
fn parent_linkage_rejects_extra_archive_member_even_when_tree_is_exact() {
    use flate2::{write::GzEncoder, Compression};
    let root = research_fixture();
    let input = inputs(root.path());
    build(&input).unwrap();
    let manifest: Manifest =
        serde_json::from_slice(&fs::read(root.path().join(MANIFEST)).unwrap()).unwrap();
    let mut files = manifest.files;
    files.insert(
        MANIFEST.into(),
        hash(&fs::read(root.path().join(MANIFEST)).unwrap()),
    );
    files.insert(
        SUMS.into(),
        hash(&fs::read(root.path().join(SUMS)).unwrap()),
    );
    let archive_owner = tempfile::tempdir().unwrap();
    let archive = archive_owner
        .path()
        .canonicalize()
        .unwrap()
        .join("private-research.tar.gz");
    for extra in [false, true] {
        let output = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&archive)
            .unwrap();
        let mut builder = tar::Builder::new(GzEncoder::new(output, Compression::fast()));
        builder
            .append_dir_all("research-root", root.path())
            .unwrap();
        if extra {
            let bytes = b"inert full administrative payload";
            let mut header = tar::Header::new_gnu();
            header.set_size(bytes.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder
                .append_data(&mut header, "research-root/bin/administrative", &bytes[..])
                .unwrap();
        }
        builder.into_inner().unwrap().finish().unwrap();
        assert_eq!(
            archive_hash(&archive, "research-root", &files).is_ok(),
            !extra
        );
        fs::remove_file(&archive).unwrap();
    }
}
