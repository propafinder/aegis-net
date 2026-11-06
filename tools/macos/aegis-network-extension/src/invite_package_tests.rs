use super::*;
use crate::{
    identity_import::tests::{relay, TempContainer},
    test_fixture::ReadyTree,
};
use std::os::unix::fs::{symlink, PermissionsExt};

/// The fixture's four public bundle files, in `MEMBERS` order.
pub(crate) fn bundle_of(tree: &ReadyTree) -> [Vec<u8>; 4] {
    MEMBERS.map(|name| std::fs::read(tree.aegis().join("bundle").join(name)).unwrap())
}

pub(crate) fn token() -> Zeroizing<String> {
    enrollment::new_invitation_token()
}

pub(crate) fn package_for(tree: &ReadyTree, token: &str) -> InvitePackage {
    InvitePackage::new(
        tree.device_id(),
        bundle_of(tree),
        Zeroizing::new(token.to_owned()),
    )
    .unwrap()
}

/// The canonical text as a parsed value, for building variants.
fn value_of(package: &InvitePackage) -> Value {
    serde_json::from_slice(&package.encode()).unwrap()
}

fn write_private(path: &Path, bytes: &[u8]) {
    std::fs::write(path, bytes).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
}

#[test]
fn invite_package_round_trips_its_canonical_bytes_and_hides_the_token() {
    let tree = ReadyTree::new(relay());
    let secret = token();
    let package = package_for(&tree, &secret);
    let bytes = package.encode();
    let text = std::str::from_utf8(&bytes).unwrap();
    assert!(
        text.starts_with("{\"bundle\":{\"bundle.json\":"),
        "{text:.40}"
    );
    assert!(text.ends_with(&format!(",\"schema\":\"{SCHEMA}\"}}")));
    let parsed = InvitePackage::parse(&bytes).unwrap();
    assert_eq!(parsed.device_id(), tree.device_id());
    assert_eq!(parsed.public(), &bundle_of(&tree));
    assert_eq!(parsed.token(), secret.as_str());
    assert_eq!(parsed.profile_sha256(), tree.profile_sha256());
    // One trailing newline is accepted (an editor or `echo` adds it).
    let mut newline = bytes.to_vec();
    newline.push(b'\n');
    assert!(InvitePackage::parse(&newline).is_ok());
    // Debug never shows the token.
    let shown = format!("{parsed:?}");
    assert!(!shown.contains(secret.as_str()), "{shown}");
    assert!(shown.contains("<redacted>"));
}

#[test]
fn invite_package_refuses_every_non_canonical_or_foreign_shape() {
    let tree = ReadyTree::new(relay());
    let package = package_for(&tree, &token());
    let canonical = package.encode().to_vec();
    let refuse = |bytes: &[u8]| InvitePackage::parse(bytes).expect_err("admitted");

    // Padding, pretty printing, a second newline, another key order.
    let mut two = canonical.clone();
    two.extend_from_slice(b"\n\n");
    assert_eq!(refuse(&two), "invite_not_canonical");
    let pretty = serde_json::to_vec_pretty(&value_of(&package)).unwrap();
    assert_eq!(refuse(&pretty), "invite_not_canonical");
    let mut spaced = b" ".to_vec();
    spaced.extend_from_slice(&canonical);
    assert_eq!(refuse(&spaced), "invite_not_canonical");
    let text = String::from_utf8(canonical.clone()).unwrap();
    let schema_first = format!(
        "{{\"schema\":\"{SCHEMA}\",{}",
        text.trim_start_matches('{')
            .replace(&format!(",\"schema\":\"{SCHEMA}\""), "")
    );
    assert_eq!(refuse(schema_first.as_bytes()), "invite_not_canonical");
    // A duplicate key (serde_json keeps the last one) is refused.
    let duplicate = text.replacen(
        "\"device_id\":",
        "\"device_id\":\"other-device\",\"device_id\":",
        1,
    );
    assert_eq!(refuse(duplicate.as_bytes()), "invite_not_canonical");
    // Unknown, missing and wrongly typed keys.
    let mut unknown = value_of(&package);
    unknown["note"] = "hello".into();
    assert_eq!(
        refuse(&serde_json::to_vec(&unknown).unwrap()),
        "invite_not_canonical"
    );
    let mut missing = value_of(&package);
    missing.as_object_mut().unwrap().remove("invitation");
    assert_eq!(
        refuse(&serde_json::to_vec(&missing).unwrap()),
        "invite_not_canonical"
    );
    let mut extra_member = value_of(&package);
    extra_member["bundle"]["runtime.json"] = "{}".into();
    assert_eq!(
        refuse(&serde_json::to_vec(&extra_member).unwrap()),
        "invite_not_canonical"
    );
    let mut number = value_of(&package);
    number["device_id"] = 7.into();
    assert_eq!(
        refuse(&serde_json::to_vec(&number).unwrap()),
        "invite_device_id_invalid"
    );
    // Another schema, another top-level type, not JSON at all.
    let mut schema = value_of(&package);
    schema["schema"] = "aegis_device_invite_v2".into();
    assert_eq!(
        refuse(&serde_json::to_vec(&schema).unwrap()),
        "invite_schema_mismatch"
    );
    assert_eq!(refuse(b"[]"), "invite_not_canonical");
    assert_eq!(refuse(b"not json"), "invite_not_canonical");
    assert_eq!(refuse(b""), "invite_not_canonical");
    // The cap is checked before parsing.
    assert_eq!(
        refuse(&vec![b' '; MAX_PACKAGE_BYTES + 1]),
        "invite_oversized"
    );
}

#[test]
fn invite_package_validates_device_id_token_and_the_bundle_itself() {
    let tree = ReadyTree::new(relay());
    let bundle = bundle_of(&tree);
    let make = |device: &str, public: [Vec<u8>; 4], token: &str| {
        InvitePackage::new(device, public, Zeroizing::new(token.to_owned())).expect_err("admitted")
    };
    let good = token();
    for device in ["", "has space", "slash/name", &"d".repeat(65), "dévice"] {
        assert_eq!(
            make(device, bundle.clone(), &good),
            "invite_device_id_invalid",
            "{device}"
        );
    }
    for bad in [
        "",
        "abc",
        &"A".repeat(64),
        &"g".repeat(64),
        &"a".repeat(63),
        &"a".repeat(65),
        &format!("{} ", "a".repeat(64)),
    ] {
        assert_eq!(
            make(tree.device_id(), bundle.clone(), bad),
            "invite_token_invalid",
            "{bad:?}"
        );
    }
    // An empty member, a private key, a member above the public cap.
    let mut empty = bundle.clone();
    empty[1] = Vec::new();
    assert_eq!(
        make(tree.device_id(), empty, &good),
        "invite_bundle_member_invalid"
    );
    let mut private = bundle.clone();
    private[2]
        .extend_from_slice(b"\n-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n");
    assert_eq!(
        make(tree.device_id(), private, &good),
        "invite_bundle_member_invalid"
    );
    let mut large = bundle.clone();
    large[0] = vec![b' '; 64 * 1024 + 1];
    assert_eq!(
        make(tree.device_id(), large, &good),
        "invite_bundle_member_invalid"
    );
    // The production profile validator, the profile kind and every CA.
    let mut profile: Value = serde_json::from_slice(&bundle[0]).unwrap();
    let mut socks = profile.clone();
    socks["product_mode"] = "socks-only".into();
    socks.as_object_mut().unwrap().remove("macos_packet");
    let mut public = bundle.clone();
    public[0] = serde_json::to_vec(&socks).unwrap();
    assert_eq!(
        make(tree.device_id(), public, &good),
        "invite_bundle_invalid"
    );
    profile.as_object_mut().unwrap().remove("enrollment");
    let mut public = bundle.clone();
    public[0] = serde_json::to_vec(&profile).unwrap();
    assert_eq!(
        make(tree.device_id(), public, &good),
        "invite_bundle_invalid"
    );
    let mut public = bundle.clone();
    public[0] = b"{\"schema\":\"aegis_device_bundle_v4\"}".to_vec();
    assert_eq!(
        make(tree.device_id(), public, &good),
        "invite_bundle_invalid"
    );
    let mut public = bundle.clone();
    public[3] =
        b"-----BEGIN CERTIFICATE-----\nnot a certificate\n-----END CERTIFICATE-----\n".to_vec();
    assert_eq!(
        make(tree.device_id(), public, &good),
        "invite_bundle_invalid"
    );
    assert!(InvitePackage::new(tree.device_id(), bundle, good).is_ok());
}

#[test]
fn invite_staging_name_is_stable_per_package_and_never_the_token() {
    let tree = ReadyTree::new(relay());
    let first = token();
    let a = package_for(&tree, &first);
    let again = package_for(&tree, &first);
    let other = package_for(&tree, &token());
    let name = a.staging_name();
    assert_eq!(name.len(), 32);
    assert!(name
        .bytes()
        .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()));
    assert_eq!(name, again.staging_name());
    assert_ne!(name, other.staging_name());
    assert!(!first.contains(&name));
    let digest = sha_hex(first.as_bytes());
    assert!(!digest.contains(&name));
    // Another device id over the same bundle and token is another stage.
    let renamed = InvitePackage::new("another-device", bundle_of(&tree), first.clone()).unwrap();
    assert_ne!(renamed.staging_name(), name);
}

#[test]
fn invite_file_must_be_an_absolute_canonical_private_regular_file() {
    let tree = ReadyTree::new(relay());
    let dir = TempContainer::new();
    let package = package_for(&tree, &token());
    let path = dir.path().join("friend.aegis-invite");
    write_private(&path, &package.encode());
    let (read, source) = read_package(&path).unwrap();
    assert_eq!(read.token(), package.token());

    let refuse = |path: &Path| read_package(path).expect_err("admitted");
    assert_eq!(
        refuse(Path::new("friend.aegis-invite")),
        "invite_path_not_absolute"
    );
    let wrong = dir.path().join("friend.json");
    write_private(&wrong, &package.encode());
    assert_eq!(refuse(&wrong), "invite_extension_required");
    assert_eq!(
        refuse(&dir.path().join(".aegis-invite")),
        "invite_extension_required"
    );
    assert_eq!(
        refuse(&dir.path().join("absent.aegis-invite")),
        "invite_missing"
    );
    let link = dir.path().join("link.aegis-invite");
    symlink(&path, &link).unwrap();
    assert_eq!(refuse(&link), "invite_symlink");
    let folder = dir.path().join("folder.aegis-invite");
    std::fs::create_dir(&folder).unwrap();
    assert_eq!(refuse(&folder), "invite_not_regular");
    let via = dir.path().join("sub");
    std::fs::create_dir(&via).unwrap();
    let dotted = via.join("..").join("friend.aegis-invite");
    assert_eq!(refuse(&dotted), "invite_not_canonical_path");
    let hard = dir.path().join("hard.aegis-invite");
    std::fs::hard_link(&path, &hard).unwrap();
    assert_eq!(refuse(&hard), "invite_linked");
    std::fs::remove_file(&hard).unwrap();
    let shared = dir.path().join("shared.aegis-invite");
    write_private(&shared, &package.encode());
    std::fs::set_permissions(&shared, std::fs::Permissions::from_mode(0o620)).unwrap();
    assert_eq!(refuse(&shared), "invite_writable_by_others");
    // Readable by others is accepted: a download is 0644.
    std::fs::set_permissions(&shared, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(read_package(&shared).is_ok());
    let big = dir.path().join("big.aegis-invite");
    write_private(&big, &vec![b' '; MAX_PACKAGE_BYTES + 1]);
    assert_eq!(refuse(&big), "invite_oversized");
    let garbage = dir.path().join("garbage.aegis-invite");
    write_private(&garbage, b"{}");
    assert_eq!(refuse(&garbage), "invite_not_canonical");
    for code in [
        "invite_path_not_absolute",
        "invite_extension_required",
        "invite_missing",
        "invite_symlink",
        "invite_not_regular",
        "invite_not_canonical_path",
        "invite_linked",
        "invite_writable_by_others",
        "invite_oversized",
        "invite_not_canonical",
    ] {
        assert!(CODES.contains(&code), "{code}");
    }

    // Removal takes exactly the file that was read.
    let changed = dir.path().join("changed.aegis-invite");
    write_private(&changed, &package.encode());
    let (_, changed_source) = read_package(&changed).unwrap();
    let mut edited = package.encode().to_vec();
    edited.push(b'\n');
    std::fs::write(&changed, &edited).unwrap();
    assert_eq!(
        remove_package(&changed, &changed_source),
        Err("invite_changed")
    );
    assert!(changed.exists());
    let replaced = dir.path().join("replaced.aegis-invite");
    write_private(&replaced, &package.encode());
    let (_, replaced_source) = read_package(&replaced).unwrap();
    std::fs::remove_file(&replaced).unwrap();
    write_private(&replaced, &package.encode());
    assert_eq!(
        remove_package(&replaced, &replaced_source),
        Err("invite_changed")
    );
    assert!(replaced.exists());
    assert_eq!(remove_package(&path, &source), Ok(()));
    assert!(!path.exists());
}

#[test]
fn the_menu_copies_a_chosen_package_into_its_private_inbox() {
    let tree = ReadyTree::new(relay());
    let home = TempContainer::new();
    let package = package_for(&tree, &token());
    let downloads = home.path().join("Downloads");
    std::fs::create_dir(&downloads).unwrap();
    let original = downloads.join("friend.aegis-invite");
    std::fs::write(&original, package.encode().as_slice()).unwrap();
    // A download is readable by others.
    std::fs::set_permissions(&original, std::fs::Permissions::from_mode(0o644)).unwrap();
    let inbox = home.path().join(INBOX_DIR);

    let (copy, source) = copy_to_inbox(&original, &inbox).unwrap();
    assert_eq!(copy.parent(), Some(inbox.as_path()));
    let name = copy.file_name().unwrap().to_str().unwrap();
    assert!(
        name.starts_with("join-") && name.ends_with(".aegis-invite"),
        "{name}"
    );
    use std::os::unix::fs::MetadataExt;
    assert_eq!(std::fs::metadata(&copy).unwrap().mode() & 0o7777, 0o600);
    assert_eq!(std::fs::metadata(&inbox).unwrap().mode() & 0o7777, 0o700);
    assert_eq!(std::fs::read(&copy).unwrap(), package.encode().to_vec());
    // The host admits the copy as the same package.
    let (again, _) = read_package(&copy).unwrap();
    assert_eq!(again.staging_name(), package.staging_name());
    // Two copies never collide.
    let (second, _) = copy_to_inbox(&original, &inbox).unwrap();
    assert_ne!(second, copy);

    // Only the app's own copies are discarded.
    let foreign = inbox.join("other.aegis-invite");
    write_private(&foreign, b"x");
    discard_inbox_copy(&foreign, &inbox);
    assert!(foreign.exists());
    discard_inbox_copy(&copy, home.path());
    assert!(copy.exists());
    discard_inbox_copy(&copy, &inbox);
    assert!(!copy.exists());

    // The original goes only on request, and only that file.
    assert_eq!(remove_package(&original, &source), Ok(()));
    assert!(!original.exists());

    // A refused package is never copied; a relative or shared inbox is refused.
    let bad = downloads.join("bad.aegis-invite");
    write_private(&bad, b"{}");
    assert_eq!(
        copy_to_inbox(&bad, &inbox).err(),
        Some("invite_not_canonical")
    );
    let ok = downloads.join("ok.aegis-invite");
    write_private(&ok, &package.encode());
    assert_eq!(
        copy_to_inbox(&ok, Path::new("relative/inbox")).err(),
        Some("invite_inbox_refused")
    );
    let shared = home.path().join("shared-inbox");
    std::fs::create_dir(&shared).unwrap();
    std::fs::set_permissions(&shared, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert_eq!(
        copy_to_inbox(&ok, &shared).err(),
        Some("invite_inbox_refused")
    );
}

/// The operator script's output (`tools/macos/relay-ops/make-invite.py`,
/// run against its fake ssh, never a relay) is exactly what the host
/// admits: the same canonical bytes, the fixture's real bundle.
#[test]
fn the_operator_script_writes_a_package_the_host_admits() {
    let tree = ReadyTree::new(relay());
    let work = TempContainer::new();
    let bundle = work.path().join("bundle");
    std::fs::create_dir(&bundle).unwrap();
    for (name, bytes) in MEMBERS.iter().zip(bundle_of(&tree)) {
        std::fs::write(bundle.join(name), bytes).unwrap();
    }
    let ops = Path::new(env!("CARGO_MANIFEST_DIR")).join("../relay-ops");
    let bin = work.path().join("bin");
    std::fs::create_dir(&bin).unwrap();
    std::fs::copy(ops.join("testdata/fake-ssh"), bin.join("ssh")).unwrap();
    std::fs::set_permissions(bin.join("ssh"), std::fs::Permissions::from_mode(0o755)).unwrap();
    let config = work.path().join("ssh-config");
    write_private(&config, b"Host relay-a\n");
    let out = work.path().join("friend.aegis-invite");
    let secret = token();
    let done = std::process::Command::new("/usr/bin/python3")
        .args(["-I", "-B"])
        .arg(ops.join("make-invite.py"))
        .args(["--device-id", tree.device_id(), "--bundle-dir"])
        .arg(&bundle)
        .arg("--out")
        .arg(&out)
        .arg("--ssh-config")
        .arg(&config)
        .arg("--lock-file")
        .arg(work.path().join("invite.lock"))
        .env_clear()
        .env("PATH", format!("{}:/usr/bin:/bin", bin.display()))
        .env("HOME", work.path())
        .env("FAKE_SSH_TOKEN", secret.as_str())
        .output()
        .unwrap();
    assert!(
        done.status.success(),
        "{}",
        String::from_utf8_lossy(&done.stderr)
    );
    let shown = format!(
        "{}{}",
        String::from_utf8_lossy(&done.stdout),
        String::from_utf8_lossy(&done.stderr)
    );
    assert!(!shown.contains(secret.as_str()));
    use std::os::unix::fs::MetadataExt;
    assert_eq!(std::fs::metadata(&out).unwrap().mode() & 0o7777, 0o600);
    let (package, _) = read_package(&out).unwrap();
    assert_eq!(package.token(), secret.as_str());
    assert_eq!(package.device_id(), tree.device_id());
    assert_eq!(package.profile_sha256(), tree.profile_sha256());
    assert_eq!(std::fs::read(&out).unwrap(), package.encode().to_vec());
}

#[test]
fn removal_follows_the_held_parent_and_the_inbox_is_swept_at_start() {
    let tree = ReadyTree::new(relay());
    let home = TempContainer::new();
    let package = package_for(&tree, &token());
    // The parent swapped for a link to another folder holding a file of the
    // same name: that other file is never removed.
    let real = home.path().join("real");
    let other = home.path().join("other");
    std::fs::create_dir(&real).unwrap();
    std::fs::create_dir(&other).unwrap();
    let original = real.join("friend.aegis-invite");
    write_private(&original, &package.encode());
    let (_, source) = read_package(&original).unwrap();
    std::fs::rename(&real, home.path().join("moved")).unwrap();
    write_private(&other.join("friend.aegis-invite"), &package.encode());
    symlink(&other, &real).unwrap();
    assert_eq!(remove_package(&original, &source), Err("invite_changed"));
    assert!(other.join("friend.aegis-invite").exists());
    std::fs::remove_file(&real).unwrap();
    std::fs::rename(home.path().join("moved"), &real).unwrap();
    assert_eq!(remove_package(&original, &source), Ok(()));

    // Copies a crash left behind go at the next start; nothing else does.
    let inbox = home.path().join(INBOX_DIR);
    let first = copy_to_inbox(
        &{
            let file = home.path().join("again.aegis-invite");
            write_private(&file, &package.encode());
            file
        },
        &inbox,
    )
    .unwrap()
    .0;
    let foreign = inbox.join("keep.txt");
    write_private(&foreign, b"x");
    assert_eq!(sweep_inbox(&inbox), 1);
    assert!(!first.exists() && foreign.exists());
    // The inbox is excluded from Time Machine.
    let mut value = [0u8; 64];
    use std::os::unix::ffi::OsStrExt;
    let path = std::ffi::CString::new(inbox.as_os_str().as_bytes()).unwrap();
    let length = unsafe {
        libc::getxattr(
            path.as_ptr(),
            crate::identity_import::BACKUP_EXCLUDE_XATTR.as_ptr(),
            value.as_mut_ptr().cast(),
            value.len(),
            0,
            libc::XATTR_NOFOLLOW,
        )
    };
    assert!(length > 0, "no backup exclusion on the inbox");
}
