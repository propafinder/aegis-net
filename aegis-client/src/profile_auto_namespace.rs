//! PRIVATE UNAPPLIED: original-absence-preserving administrative parent creation.
//! New ancestors only; never chmod/chown existing objects or mkdir a target leaf.
//! Every mutation is preceded by protected intent and followed by exact FD receipt.
use super::authority::Manifest;
use super::authority::StageGuard;
use super::durable::Store;
use super::{absolute, digest, refuse, Header, Phase, Result};
use crate::profile_auto_capture::{self as capture, GenerationRecord};
use serde::{Deserialize, Serialize};
use std::{
    ffi::{CStr, CString},
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd, RawFd},
        unix::ffi::OsStrExt,
    },
    path::{Component, Path, PathBuf},
};

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Node {
    path: PathBuf,
    dev: u64,
    ino: u64,
    uid: u32,
    gid: u32,
    mode: u32,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ParentProof {
    schema: u32,
    transaction_nonce: String,
    role: String,
    target: PathBuf,
    original_sha256: String,
    nodes: Vec<Node>,
    created: Vec<PathBuf>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DirectoryIntent {
    schema: u32,
    transaction_nonce: String,
    role: String,
    target: PathBuf,
    original_sha256: String,
    parent: Node,
    name: String,
    new_uid: u32,
    new_gid: u32,
    new_mode: u32,
}
fn raw(fd: RawFd) -> Result<OwnedFd> {
    if fd < 0 {
        Err(refuse())
    } else {
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    }
}
fn c(bytes: &[u8]) -> Result<CString> {
    CString::new(bytes).map_err(|_| refuse())
}
fn try_dir(parent: RawFd, name: &CStr) -> std::io::Result<OwnedFd> {
    let fd = unsafe {
        libc::openat(
            parent,
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        let error = std::io::Error::last_os_error();
        Err(error)
    } else {
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    }
}
fn dir(parent: RawFd, name: &CStr) -> Result<OwnedFd> {
    try_dir(parent, name).map_err(|_| refuse())
}
fn node(fd: RawFd, path: &Path, admin: u32) -> Result<Node> {
    let mut st = std::mem::MaybeUninit::<libc::stat>::uninit();
    if unsafe { libc::fstat(fd, st.as_mut_ptr()) } != 0 {
        return Err(refuse());
    }
    let st = unsafe { st.assume_init() };
    let sticky = path == Path::new("/tmp") && st.st_uid == 0 && st.st_mode & libc::S_ISVTX != 0;
    if st.st_mode & libc::S_IFMT != libc::S_IFDIR
        || !(st.st_uid == 0 || st.st_uid == admin)
        || (st.st_mode & 0o022 != 0 && !sticky)
    {
        return Err(refuse());
    }
    Ok(Node {
        path: path.to_path_buf(),
        dev: st.st_dev,
        ino: st.st_ino,
        uid: st.st_uid,
        gid: st.st_gid,
        mode: st.st_mode,
    })
}
fn root(admin: u32) -> Result<(OwnedFd, Node)> {
    let fd = raw(unsafe {
        libc::open(
            c(b"/")?.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    })?;
    let n = node(fd.as_raw_fd(), Path::new("/"), admin)?;
    Ok((fd, n))
}
fn source_parts<'a>(
    store: &Store,
    header: &Header,
    manifest: &'a Manifest,
    role: &str,
) -> Result<(&'a Path, GenerationRecord, String)> {
    if !matches!(role, "config" | "state" | "metadata") {
        return Err(refuse());
    }
    let src = manifest
        .sources
        .iter()
        .find(|s| s.role == role)
        .ok_or_else(refuse)?;
    let bytes = store.read(&src.generation_leaf)?;
    let hash = digest(&bytes);
    if header.leaves.get(&src.generation_leaf) != Some(&hash) {
        return Err(refuse());
    }
    let record: GenerationRecord = serde_json::from_slice(&bytes).map_err(|_| refuse())?;
    if record.original_source() != src.original_path || !matches!(record.kind(), 0 | 2) {
        return Err(refuse());
    }
    Ok((&src.original_path, record, hash))
}
fn source<'a>(g: &'a StageGuard, role: &str) -> Result<(&'a Path, GenerationRecord, String)> {
    source_parts(&g.store, &g.header, &g.manifest, role)
}

fn record(g: &mut StageGuard, path: &Path, bytes: &[u8]) -> Result<()> {
    if !path.starts_with("receipts/namespaces") || bytes.len() > 1024 * 1024 {
        return Err(refuse());
    }
    g.store.write_new(path, bytes)?;
    g.header
        .namespace_records
        .insert(path.to_path_buf(), digest(bytes));
    g.persist_header()
}
fn proof_leaf(role: &str) -> PathBuf {
    PathBuf::from(format!("receipts/namespaces/{role}-parents.json"))
}
/// Called only after source capture/planning; held original namespace admission
/// remains valid immediately before each fresh component. Proof reentry uses
/// descriptor-minted created identities, not a blind original-absence bypass.
pub(super) fn ensure_sealed_parent(g: &mut StageGuard, role: &str) -> Result<()> {
    if unsafe { libc::geteuid() } != 0 {
        return Err(refuse());
    }
    ensure_actor(g, role, 0)
}
fn ensure_actor(g: &mut StageGuard, role: &str, admin: u32) -> Result<()> {
    g.store.revalidate()?;
    let leaf = proof_leaf(role);
    if g.header.namespace_records.contains_key(&leaf) {
        return validate_sealed_parent(g, role, false);
    }
    if g.header.capture_started
        || g.header.pending.is_some()
        || !matches!(
            (role, g.header.phase),
            ("config", Phase::Prepared) | ("state", Phase::Custody) | ("metadata", Phase::Config)
        )
    {
        return Err(refuse());
    }
    let (target, record_original, original_sha256) = source(g, role)?;
    let target = target.to_path_buf();
    if !absolute(&target) {
        return Err(refuse());
    }
    capture::reopen_generation(&record_original)
        .and_then(|r| r.revalidate())
        .map_err(|_| refuse())?;
    let parent = target.parent().ok_or_else(refuse)?;
    let (mut held, first) = root(admin)?;
    let mut nodes = vec![first];
    let mut created = Vec::new();
    let mut current = PathBuf::from("/");
    for part in parent.components() {
        let Component::Normal(name) = part else {
            continue;
        };
        let name = c(name.as_bytes())?;
        current.push(part.as_os_str());
        let child = match try_dir(held.as_raw_fd(), &name) {
            Ok(fd) => fd,
            Err(error) if error.raw_os_error() == Some(libc::ENOENT) => {
                // Only an originally absent target may need new parent components.
                if record_original.kind() != 2 {
                    return Err(refuse());
                }
                if created.is_empty() {
                    capture::reopen_generation(&record_original)
                        .and_then(|r| r.revalidate())
                        .map_err(|_| refuse())?;
                }
                let parent_node = nodes.last().ok_or_else(refuse)?.clone();
                if parent_node.uid != admin || parent_node.path == Path::new("/tmp") {
                    return Err(refuse());
                }
                let number = created.len();
                if number >= 8 {
                    return Err(refuse());
                }
                let intent = DirectoryIntent {
                    schema: 1,
                    transaction_nonce: g.header.transaction_nonce.clone(),
                    role: role.into(),
                    target: target.clone(),
                    original_sha256: original_sha256.clone(),
                    parent: parent_node,
                    name: name.to_str().map_err(|_| refuse())?.into(),
                    new_uid: admin,
                    new_gid: unsafe { libc::getegid() },
                    new_mode: 0o755,
                };
                record(
                    g,
                    &PathBuf::from(format!(
                        "receipts/namespaces/{role}-{number:04}-intent.json"
                    )),
                    &serde_json::to_vec(&intent).map_err(|_| refuse())?,
                )?;
                if unsafe { libc::mkdirat(held.as_raw_fd(), name.as_ptr(), 0o700) } != 0 {
                    return Err(refuse());
                }
                let fd = dir(held.as_raw_fd(), &name)?;
                if unsafe { libc::fchown(fd.as_raw_fd(), admin, libc::getegid()) } != 0
                    || unsafe { libc::fchmod(fd.as_raw_fd(), 0o755) } != 0
                {
                    return Err(refuse());
                }
                let actual = node(fd.as_raw_fd(), &current, admin)?;
                if actual.uid != admin
                    || actual.gid != unsafe { libc::getegid() }
                    || actual.mode & 0o7777 != 0o755
                {
                    return Err(refuse());
                }
                if unsafe { libc::fsync(held.as_raw_fd()) } != 0 {
                    return Err(refuse());
                }
                record(
                    g,
                    &PathBuf::from(format!(
                        "receipts/namespaces/{role}-{number:04}-receipt.json"
                    )),
                    &serde_json::to_vec(&actual).map_err(|_| refuse())?,
                )?;
                created.push(current.clone());
                fd
            }
            Err(_) => return Err(refuse()),
        };
        let n = node(child.as_raw_fd(), &current, admin)?;
        nodes.push(n);
        held = child;
    }
    if nodes.last().ok_or_else(refuse)?.uid != admin {
        return Err(refuse());
    }
    // Last target leaf must still satisfy original absence; current namespace
    // after own parent creation is established through held FD, never bytes.
    if record_original.kind() == 2 {
        let name = c(target.file_name().ok_or_else(refuse)?.as_bytes())?;
        let mut st = std::mem::MaybeUninit::<libc::stat>::uninit();
        if unsafe {
            libc::fstatat(
                held.as_raw_fd(),
                name.as_ptr(),
                st.as_mut_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        } == 0
            || std::io::Error::last_os_error().raw_os_error() != Some(libc::ENOENT)
        {
            return Err(refuse());
        }
    }
    let proof = ParentProof {
        schema: 1,
        transaction_nonce: g.header.transaction_nonce.clone(),
        role: role.into(),
        target,
        original_sha256,
        nodes,
        created,
    };
    record(g, &leaf, &serde_json::to_vec(&proof).map_err(|_| refuse())?)?;
    validate_sealed_parent(g, role, record_original.kind() == 2)
}
/// For initial absent publication, require target leaf STILL absent and every
/// original/new ancestor equal the protected FD proof. Current-own publication
/// permits the own target leaf; it never relaxes ancestor identity/permissions.
pub(super) fn validate_sealed_parent(
    g: &StageGuard,
    role: &str,
    require_target_absent: bool,
) -> Result<()> {
    validate_sealed_parent_parts(
        &g.store,
        &g.header,
        &g.manifest,
        role,
        require_target_absent,
    )
}
pub(super) fn validate_sealed_parent_parts(
    store: &Store,
    header: &Header,
    manifest: &Manifest,
    role: &str,
    require_target_absent: bool,
) -> Result<()> {
    header.validate(unsafe { libc::geteuid() })?;
    manifest.validate(header)?;
    store.revalidate()?;
    let leaf = proof_leaf(role);
    let expected = header.namespace_records.get(&leaf).ok_or_else(refuse)?;
    let bytes = store.read(&leaf)?;
    if &digest(&bytes) != expected {
        return Err(refuse());
    }
    let proof: ParentProof = serde_json::from_slice(&bytes).map_err(|_| refuse())?;
    let (target, original, source_hash) = source_parts(store, header, manifest, role)?;
    if proof.schema != 1
        || proof.role != role
        || proof.transaction_nonce != header.transaction_nonce
        || proof.target != target
        || proof.original_sha256 != source_hash
        || proof.nodes.len() > 64
        || proof.nodes.is_empty()
        || proof.created.len() > 8
    {
        return Err(refuse());
    }
    if !proof.created.is_empty() && original.kind() != 2 {
        return Err(refuse());
    }
    let admin = header.administrator_uid;
    let (mut held, first) = root(admin)?;
    let mut actual = vec![first];
    let mut current = PathBuf::from("/");
    for part in target.parent().ok_or_else(refuse)?.components() {
        if let Component::Normal(name) = part {
            current.push(part.as_os_str());
            held = dir(held.as_raw_fd(), &c(name.as_bytes())?)?;
            actual.push(node(held.as_raw_fd(), &current, admin)?);
        }
    }
    if actual != proof.nodes || actual.last().ok_or_else(refuse)?.uid != admin {
        return Err(refuse());
    }
    for (number, p) in proof.created.iter().enumerate() {
        let receipt = PathBuf::from(format!(
            "receipts/namespaces/{role}-{number:04}-receipt.json"
        ));
        let data = store.read(&receipt)?;
        if header.namespace_records.get(&receipt) != Some(&digest(&data)) {
            return Err(refuse());
        }
        let n: Node = serde_json::from_slice(&data).map_err(|_| refuse())?;
        if &n.path != p || !actual.contains(&n) {
            return Err(refuse());
        }
    }
    if require_target_absent {
        if original.kind() != 2 {
            return Err(refuse());
        }
        let name = c(target.file_name().ok_or_else(refuse)?.as_bytes())?;
        let mut st = std::mem::MaybeUninit::<libc::stat>::uninit();
        if unsafe {
            libc::fstatat(
                held.as_raw_fd(),
                name.as_ptr(),
                st.as_mut_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        } == 0
            || std::io::Error::last_os_error().raw_os_error() != Some(libc::ENOENT)
        {
            return Err(refuse());
        }
    }
    store.revalidate()
}

#[cfg(test)]
mod tests {
    use super::super::authority::{Manifest, SourceBinding};
    use super::super::durable::Store;
    use super::super::{AutoMode, Header, PROTOCOL};
    use super::*;
    use crate::profile_auto_capture::{CaptureLimits, CapturedTree, InputRole};
    use std::{
        collections::BTreeMap,
        os::unix::fs::{symlink, PermissionsExt},
    };
    struct Fixture {
        root: PathBuf,
        guard: Option<StageGuard>,
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }
    fn fixture() -> Fixture {
        let uid = unsafe { libc::geteuid() };
        let base =
            std::env::temp_dir().join(format!(".auto-namespace-{:032x}", rand::random::<u128>()));
        std::fs::create_dir(&base).unwrap();
        std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o700)).unwrap();
        let config = base.join("new-parent/client");
        let state = base.join("state");
        let metadata = base.join("metadata");
        for p in [&state, &metadata] {
            std::fs::create_dir(p).unwrap();
            std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let mut sources = Vec::new();
        let mut records = BTreeMap::new();
        for (role, path) in [
            ("config", &config),
            ("state", &state),
            ("metadata", &metadata),
        ] {
            let input = CapturedTree::capture_optional(
                path,
                path.to_path_buf(),
                if role == "metadata" {
                    InputRole::AdministratorMetadata {
                        administrator_uid: uid,
                    }
                } else {
                    InputRole::ServiceInput {
                        service_uid: uid,
                        administrator_uid: uid,
                    }
                },
                CaptureLimits::default(),
                true,
            )
            .unwrap();
            let leaf = PathBuf::from(format!("input/generations/{role}.json"));
            records.insert(
                leaf.clone(),
                serde_json::to_vec(&input.export_private_generation().unwrap()).unwrap(),
            );
            sources.push(SourceBinding {
                role: role.into(),
                original_path: path.to_path_buf(),
                generation_leaf: leaf,
                publication_witness_leaf: None,
            });
        }
        let manifest = Manifest {
            schema: 1,
            config_root: config.clone(),
            state_dir: state.clone(),
            metadata_dir: metadata.clone(),
            service_uid: uid,
            operator_uid: uid,
            logical_bundle: None,
            render_context: crate::profile_auto_render::RenderContext {
                mode: crate::profile_auto_render::SelectedMode::SocksOnly,
                logical_original_base: config.clone(),
                logical_final_base: config.clone(),
                final_state: state.join("state.json"),
                wide_interface: Some("eth0".into()),
            },
            sources,
            references: Vec::new(),
        };
        records.insert(
            "input/authority.json".into(),
            serde_json::to_vec(&manifest).unwrap(),
        );
        let store = Store::create(&base, uid).unwrap();
        let hashes = records
            .iter()
            .map(|(p, b)| (p.clone(), digest(b)))
            .collect();
        for (p, b) in records {
            store.write_new(&p, &b).unwrap();
        }
        let header = Header {
            protocol: PROTOCOL.into(),
            administrator_uid: uid,
            config_root: config,
            state_dir: state,
            metadata_dir: metadata,
            phase: Phase::Prepared,
            transaction_nonce: "00112233445566778899aabbccddeeff".into(),
            current_records: BTreeMap::new(),
            active_records: BTreeMap::new(),
            pending: None,
            mode: AutoMode::SocksOnly,
            plan: serde_json::json!({"schema":"aegis_auto_install_plan_v1","status":"planned","product_mode":"socks-only","connectivity_verified":false}),
            old_unit_namespace: None,
            new_unit_namespace: None,
            runtime_events: "/dev/null".into(),
            unit_policy_recipe: None,
            unit_records: BTreeMap::new(),
            unit_role_records: BTreeMap::new(),
            unit_pending: None,
            unit_forward_transitions: BTreeMap::new(),
            unit_restorations: BTreeMap::new(),
            unit_restored_manager: None,
            runtime_binding: None,
            installed_receipt_recipe: None,
            service_uid: None,
            service_gid: None,
            state_records: BTreeMap::new(),
            namespace_records: BTreeMap::new(),
            service_was_active: None,
            capture_started: false,
            leaves: hashes,
            input_generation: "01".repeat(32),
            accepted_generation: "02".repeat(32),
            planned_generation: "02".repeat(32),
            render_recipe: "accepted/render-recipe.json".into(),
        };
        store.save_header(&header).unwrap();
        Fixture {
            root: base,
            guard: Some(StageGuard::admit_fixture(store, uid).unwrap()),
        }
    }
    #[test]
    fn actual_missing_default_style_parent_is_created_with_owned_proof_not_absence_bypass() {
        let mut f = fixture();
        let g = f.guard.as_mut().unwrap();
        let uid = g.header.administrator_uid;
        ensure_actor(g, "config", uid).unwrap();
        assert!(g.header.config_root.parent().unwrap().is_dir());
        assert!(!g.header.config_root.exists());
        assert_eq!(
            std::fs::metadata(g.header.config_root.parent().unwrap())
                .unwrap()
                .permissions()
                .mode()
                & 0o7777,
            0o755
        );
        assert!(validate_sealed_parent(g, "config", true).is_ok());
        let (_, old, _) = source(g, "config").unwrap();
        assert!(capture::reopen_generation(&old).is_err());
    }
    #[test]
    fn state_parent_proof_is_minted_only_in_custody_and_bound_to_state_source() {
        let mut f = fixture();
        let g = f.guard.as_mut().unwrap();
        let uid = g.header.administrator_uid;
        assert!(ensure_actor(g, "state", uid).is_err());
        assert!(!g
            .header
            .namespace_records
            .contains_key(&proof_leaf("state")));
        g.header.phase = Phase::Custody;
        g.persist_header().unwrap();
        ensure_actor(g, "state", uid).unwrap();
        assert!(g
            .header
            .namespace_records
            .contains_key(&proof_leaf("state")));
        assert!(validate_sealed_parent(g, "state", false).is_ok());
        assert!(validate_sealed_parent(g, "metadata", false).is_err());
        assert!(validate_sealed_parent(g, "state", true).is_err());
    }
    #[test]
    fn actual_parent_substitution_refuses_and_preserves_unrelated_victim() {
        let mut f = fixture();
        let g = f.guard.as_mut().unwrap();
        let actor = g.header.administrator_uid;
        ensure_actor(g, "config", actor).unwrap();
        let parent = g.header.config_root.parent().unwrap().to_path_buf();
        let kept = f.root.join("kept-parent");
        std::fs::rename(&parent, &kept).unwrap();
        let victim = f.root.join("victim");
        std::fs::create_dir(&victim).unwrap();
        std::fs::write(victim.join("private"), b"unrelated").unwrap();
        symlink(&victim, &parent).unwrap();
        assert!(validate_sealed_parent(g, "config", true).is_err());
        assert_eq!(std::fs::read(victim.join("private")).unwrap(), b"unrelated");
        assert!(!victim.join("client").exists());
    }
    #[test]
    fn appearing_target_leaf_or_wrong_stage_cannot_authorize_original_absence() {
        let mut f = fixture();
        let g = f.guard.as_mut().unwrap();
        let actor = g.header.administrator_uid;
        ensure_actor(g, "config", actor).unwrap();
        std::fs::create_dir(&g.header.config_root).unwrap();
        assert!(validate_sealed_parent(g, "config", true).is_err());
        assert!(validate_sealed_parent(g, "config", false).is_ok());
        let mut other = fixture();
        assert!(validate_sealed_parent(other.guard.as_mut().unwrap(), "config", true).is_err());
    }
    #[test]
    fn preexisting_ancestor_modes_and_unrelated_bytes_are_preserved() {
        let mut f = fixture();
        let original_mode = std::fs::metadata(&f.root).unwrap().permissions().mode();
        let victim = f.root.join("unrelated");
        std::fs::write(&victim, b"preserved").unwrap();
        let g = f.guard.as_mut().unwrap();
        let actor = g.header.administrator_uid;
        ensure_actor(g, "config", actor).unwrap();
        assert_eq!(
            std::fs::metadata(&f.root).unwrap().permissions().mode(),
            original_mode
        );
        assert_eq!(std::fs::read(victim).unwrap(), b"preserved");
    }
    #[test]
    fn interrupted_unproved_parent_is_retained_and_never_adopted_as_own_receipt() {
        let mut f = fixture();
        let g = f.guard.as_mut().unwrap();
        std::fs::create_dir(g.header.config_root.parent().unwrap()).unwrap();
        assert!({
            let actor = g.header.administrator_uid;
            ensure_actor(g, "config", actor)
        }
        .is_err());
        assert!(g.header.config_root.parent().unwrap().is_dir());
        assert!(!g.header.config_root.exists());
        assert!(!g
            .header
            .namespace_records
            .contains_key(&proof_leaf("config")));
    }
}
