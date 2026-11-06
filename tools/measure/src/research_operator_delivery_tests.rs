use super::*;
use crate::research_operator_bundle_contract_tests::{build, fixture};
fn change_info(root: &Path, field: &str, value: Value) {
    let path = root.join("research/aegis-measure.build-info.json");
    let mut info: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    info[field] = value;
    fs::write(&path, serde_json::to_vec(&info).unwrap()).unwrap();
}
#[test]
fn real_tool_and_capture_partial_pair_refuses_before_manifest_write() {
    for path in [
        "bin/aegis-measure",
        "research/aegis-transport-lab.build-info.json",
    ] {
        let root = fixture();
        fs::remove_file(root.path().join(path)).unwrap();
        assert!(build(root.path()).is_err());
        assert!(!root.path().join("bundle.manifest.json").exists());
        assert!(!root.path().join("SHA256SUMS").exists());
    }
}
#[test]
fn changed_source_target_version_capabilities_and_actual_leaf_hash_refuse() {
    for (field, value) in [
        (
            "source_commit",
            json!("0000000000000000000000000000000000000000"),
        ),
        ("target_triple", json!("aarch64-unknown-linux-gnu")),
        ("cargo_lock_sha256", json!("0".repeat(64))),
        ("crate_version", json!("0.3.50")),
        ("binary_sha256", json!("0".repeat(64))),
        ("capabilities", json!(["poisson-control"])),
        ("tool", json!("aegis-transport-lab")),
    ] {
        let root = fixture();
        change_info(root.path(), field, value);
        assert!(build(root.path()).is_err());
        assert!(!root.path().join("bundle.manifest.json").exists());
        assert!(!root.path().join("SHA256SUMS").exists());
    }
    let root = fixture();
    fs::write(
        root.path().join("bin/aegis-measure"),
        b"changed actual candidate",
    )
    .unwrap();
    assert!(build(root.path()).is_err());
}
#[test]
fn elf_machine_is_checked_independently_of_self_asserted_target_and_hash() {
    let root = fixture();
    let path = root.path().join("bin/aegis-measure");
    let mut bytes = fs::read(&path).unwrap();
    bytes[18..20].copy_from_slice(&183u16.to_le_bytes());
    fs::write(path, &bytes).unwrap();
    change_info(root.path(), "binary_sha256", json!(digest(&bytes)));
    assert!(build(root.path()).is_err());
}
#[test]
fn captures_and_tools_are_exact_not_linked_or_unknown_schema_inputs() {
    use std::os::unix::fs::symlink;
    let root = fixture();
    change_info(root.path(), "unreviewed", json!(true));
    assert!(build(root.path()).is_err());
    let root = fixture();
    let path = root.path().join("research/aegis-measure.build-info.json");
    let original = root.path().join("retained.json");
    fs::rename(&path, &original).unwrap();
    symlink(original, path).unwrap();
    assert!(build(root.path()).is_err());
}
#[test]
fn legacy_bundle_without_tool_pair_keeps_original_manifest_shape() {
    let root = fixture();
    for name in ["aegis-measure", "aegis-transport-lab"] {
        fs::remove_file(root.path().join(format!("bin/{name}"))).unwrap();
    }
    fs::remove_dir_all(root.path().join("research")).unwrap();
    build(root.path()).unwrap();
    let manifest: Value =
        serde_json::from_slice(&fs::read(root.path().join("bundle.manifest.json")).unwrap())
            .unwrap();
    assert!(manifest.get("research_operators").is_none());
    assert_eq!(manifest["binaries"].as_object().unwrap().len(), 2);
}

#[test]
fn packaged_composition_requires_linked_operator_guide_before_manifest_write() {
    let root = fixture();
    // Real packaged prose links this guide. A recipient without the repository
    // must not receive an otherwise accepted kit with that instruction absent.
    fs::write(
        root.path()
            .join("research/implementation-and-composition.md"),
        include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../docs/research/implementation-and-composition.md"
        )),
    )
    .unwrap();
    let guide = root.path().join("research/live-dependency-admission.md");
    if guide.exists() {
        fs::remove_file(guide).unwrap();
    }
    assert!(
        build(root.path()).is_err(),
        "private operator kit accepted composition with its dependency admission guide missing"
    );
    assert!(!root.path().join("bundle.manifest.json").exists());
    assert!(!root.path().join("SHA256SUMS").exists());
}

#[test]
fn delivered_research_links_resolve_without_checkout_and_all_guides_are_hash_bound() {
    let root = fixture();
    build(root.path()).unwrap();
    let manifest: Value =
        serde_json::from_slice(&fs::read(root.path().join("bundle.manifest.json")).unwrap())
            .unwrap();
    let guides: Vec<_> = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../packaging/research-operator-guides.txt"
    ))
    .lines()
    .collect();
    let mut links = 0;
    for name in std::iter::once("README.md").chain(guides.iter().copied()) {
        let relative = format!("research/{name}");
        let bytes = fs::read(root.path().join(&relative)).unwrap();
        assert_eq!(
            manifest["research_operators"]["leaf_sha256"][&relative],
            digest(&bytes),
            "delivered guide is absent from the admitted private leaf inventory: {name}"
        );
        // Inspect the actual staged prose and destination files. Source paths
        // are deliberately unavailable to a recipient and are not resolved here.
        let text = String::from_utf8(bytes).unwrap();
        for suffix in text.split("](").skip(1) {
            let (target, _) = suffix.split_once(')').expect("complete Markdown link");
            if target.contains("://") || target.starts_with('#') {
                continue;
            }
            let local = target.split('#').next().unwrap();
            assert!(guides.contains(&local), "{name}: undelivered link {target}");
            assert!(root.path().join("research").join(local).is_file());
            links += 1;
        }
    }
    assert!(
        links >= 10,
        "actual linked operator guide coverage disappeared"
    );
}

#[test]
fn changed_required_guide_changes_its_admitted_leaf_hash() {
    let original = fixture();
    let modified = fixture();
    let name = "research/live-dependency-admission.md";
    let mut bytes = fs::read(modified.path().join(name)).unwrap();
    bytes.extend_from_slice(b"\nSynthetic additional instruction for hash-binding control.\n");
    fs::write(modified.path().join(name), &bytes).unwrap();
    let manifests: Vec<Value> = [original.path(), modified.path()]
        .into_iter()
        .map(|path| {
            build(path).unwrap();
            serde_json::from_slice(&fs::read(path.join("bundle.manifest.json")).unwrap()).unwrap()
        })
        .collect();
    assert_ne!(
        manifests[0]["research_operators"]["leaf_sha256"][name],
        manifests[1]["research_operators"]["leaf_sha256"][name]
    );
    assert_eq!(
        manifests[1]["research_operators"]["leaf_sha256"][name],
        digest(&bytes)
    );
}

#[test]
fn private_research_payload_rejects_unlisted_hidden_config_and_source_entries() {
    for name in [".private-token", "operator-profile.json", "source.rs"] {
        let root = fixture();
        fs::write(
            root.path().join("research").join(name),
            b"synthetic fixture",
        )
        .unwrap();
        assert!(
            build(root.path()).is_err(),
            "unexpected research leaf: {name}"
        );
        assert!(!root.path().join("bundle.manifest.json").exists());
        assert!(!root.path().join("SHA256SUMS").exists());
    }
    let root = fixture();
    fs::create_dir(root.path().join("research/vendor")).unwrap();
    assert!(build(root.path()).is_err());
}

#[test]
fn required_guide_must_be_a_regular_owned_leaf_not_a_link() {
    use std::os::unix::fs::symlink;
    for hard_link in [false, true] {
        let root = fixture();
        let path = root.path().join("research/live-dependency-admission.md");
        let retained = root.path().join("retained-guide.md");
        fs::rename(&path, &retained).unwrap();
        if hard_link {
            fs::hard_link(&retained, &path).unwrap();
        } else {
            symlink(&retained, &path).unwrap();
        }
        assert!(build(root.path()).is_err());
        assert!(!root.path().join("bundle.manifest.json").exists());
        assert!(!root.path().join("SHA256SUMS").exists());
    }
}
