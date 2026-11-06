//! PRIVATE UNAPPLIED Linux AUTO prepare assembly. Capture all owned inputs before
//! planning, render exactly once, retain capture FDs for final metadata checks.
//! No resolver, service, runtime, credential path reload or publication.
//! Renderer r6 Options.wide_interface receives Some(validated interface).
use crate::profile_auto_capture::{
    CaptureLimits, CapturedInput, CapturedTree, GenerationRecord, InputRole,
};
use crate::profile_auto_render::{
    self as render, CapturedReference, InputKind, Options, PreparedRender, ReferenceSet, RelayPin,
    SelectedMode, StagedLeaf, StateTransfer, Supplementary,
};
use aegis_core::Settings;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path, PathBuf};
use zeroize::Zeroizing;

type Result<T> = std::result::Result<T, &'static str>;
const REFUSED: &str = "Administrative AUTO preparation refused";
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Role {
    Config,
    StateTarget,
    StateSource,
    AdministratorMetadata,
    BundleMain,
    BundleCa,
    BundleSupplementary,
    BundleMasque,
    Reference(usize),
}

pub(crate) struct OwnedTree {
    pub files: BTreeMap<PathBuf, Zeroizing<Vec<u8>>>,
    pub directories: BTreeSet<PathBuf>,
}
impl OwnedTree {
    fn empty() -> Self {
        Self {
            files: BTreeMap::new(),
            directories: BTreeSet::new(),
        }
    }
    fn copy(&self) -> Self {
        Self {
            files: self
                .files
                .iter()
                .map(|(p, b)| (p.clone(), Zeroizing::new(b.to_vec())))
                .collect(),
            directories: self.directories.clone(),
        }
    }
}
pub(crate) struct Request {
    pub config_root: PathBuf,
    pub state_target: PathBuf,
    pub metadata_target: PathBuf,
    pub bundle: Option<PathBuf>,
    pub service_uid: u32,
    pub operator_uid: u32,
    /// Trusted explicit expansion supplied by outer coordinator, never HOME IO.
    pub admitted_home: Option<PathBuf>,
    pub wide_interface: Option<String>,
    /// Exactly one captured resolver observation from outer coordinator.
    pub relay_pin: Option<RelayPin>,
    pub masque_server: Option<String>,
    pub explicit_masque_ca: Option<PathBuf>,
    /// Already captured service/binary markers from coordinator, never inspected here.
    pub prior_native_markers: bool,
    /// Explicit current-V2 administrator selection; never inferred from config.
    pub requested_mode: Option<String>,
}
struct RoleCapture {
    role: Role,
    input: CapturedInput,
}
struct ReferenceSpec {
    source: PathBuf,
    final_path: PathBuf,
    private: bool,
}
pub(crate) struct Targets {
    pub config: PathBuf,
    pub state: PathBuf,
    pub metadata: PathBuf,
}
pub(crate) struct StateMapping {
    pub original: Option<PathBuf>,
    /// Effective configured state reference, including a preserved custom path.
    /// The separate deferred-copy sink remains targets.state/state.json; do not
    /// infer that sink from this auxiliary reference mapping.
    /// Effective configured state reference, independently of the default copy sink.
    /// A preserved custom path remains here even when captured bytes are also
    /// copied into targets.state/state.json for legacy installer compatibility.
    pub final_path: PathBuf,
    pub relocated: bool,
}
pub(crate) struct PreparedInputs {
    pub targets: Targets,
    pub state_mapping: StateMapping,
    pub is_upgrade: bool,
    pub wide_interface: Option<String>,
    pub original_generations: BTreeMap<Role, GenerationRecord>,
    pub raw: BTreeMap<Role, OwnedTree>,
    pub accepted: BTreeMap<Role, OwnedTree>,
    pub original_reference_map: BTreeMap<Role, PathBuf>,
    pub final_reference_map: BTreeMap<Role, PathBuf>,
    pub plan: serde_json::Value,
    pub mode: String,
    pub rendered: PreparedRender,
    /// Private captured inputs retain original descriptor/credential lifetime.
    captures: Vec<RoleCapture>,
}
impl PreparedInputs {
    fn validate_render_mapping(&self) -> Result<()> {
        if self.rendered.context.logical_final_base != self.targets.config
            || self.rendered.config.logical_final_base != self.targets.config
            || self.rendered.context.logical_original_base
                != self.rendered.config.logical_original_base
            || self.rendered.context.wide_interface != self.wide_interface
        {
            return Err(REFUSED);
        }
        let rendered_state = logical(&self.targets.config, &self.rendered.context.final_state)?;
        if rendered_state != self.state_mapping.final_path {
            return Err(REFUSED);
        }
        if self.state_mapping.relocated {
            if rendered_state != self.targets.state.join("state.json")
                || self.state_mapping.original.is_none()
                || self.rendered.config.previous_state_reference.is_none()
            {
                return Err(REFUSED);
            }
        } else if self
            .state_mapping
            .original
            .as_ref()
            .is_some_and(|p| *p != rendered_state)
        {
            return Err(REFUSED);
        }
        // Copy custody is independent of whether the configured path relocated.
        // Only bytes from the captured singleton may populate an absent default.
        let state_leaf = Path::new("state.json");
        let default_sink = self.targets.state.join(state_leaf);
        let raw_target = self.raw.get(&Role::StateTarget).ok_or(REFUSED)?;
        let accepted_target = self.accepted.get(&Role::StateTarget).ok_or(REFUSED)?;
        let captured_source = self.raw.get(&Role::StateSource);
        if captured_source.is_some_and(|source| source.files.len() > 1) {
            return Err(REFUSED);
        }
        let source_bytes = captured_source.and_then(|source| source.files.values().next());
        let copy_expected = source_bytes.is_some()
            && self
                .state_mapping
                .original
                .as_ref()
                .is_some_and(|p| *p != default_sink)
            && !raw_target.files.contains_key(state_leaf);
        match (&self.rendered.state_transfer, source_bytes) {
            (Some(transfer), Some(bytes)) if copy_expected => {
                if transfer.relative_leaf != state_leaf
                    || transfer.bytes.as_slice() != bytes.as_slice()
                    || accepted_target.files.get(state_leaf).map(|b| b.as_slice())
                        != Some(bytes.as_slice())
                {
                    return Err(REFUSED);
                }
            }
            (None, _) if !copy_expected => {
                if accepted_target.files.get(state_leaf).map(|b| b.as_slice())
                    != raw_target.files.get(state_leaf).map(|b| b.as_slice())
                {
                    return Err(REFUSED);
                }
            }
            _ => return Err(REFUSED),
        }
        Ok(())
    }
    pub fn revalidate_originals(&self) -> Result<()> {
        self.validate_render_mapping()?;
        for c in &self.captures {
            c.input
                .revalidate_original_generation()
                .map_err(|_| REFUSED)?;
        }
        Ok(())
    }
}
fn absolute(p: &Path) -> bool {
    p.is_absolute()
        && p != Path::new("/")
        && p.components()
            .all(|x| matches!(x, Component::RootDir | Component::Normal(_)))
        && p.components().collect::<PathBuf>().as_os_str() == p.as_os_str()
}
fn nonoverlap(paths: &[&Path]) -> Result<()> {
    for (i, a) in paths.iter().enumerate() {
        if !absolute(a) {
            return Err(REFUSED);
        }
        for b in &paths[i + 1..] {
            if a.starts_with(b) || b.starts_with(a) {
                return Err(REFUSED);
            }
        }
    }
    Ok(())
}
fn logical(base: &Path, p: &Path) -> Result<PathBuf> {
    if p.as_os_str().is_empty() {
        return Err(REFUSED);
    }
    let input = if p.is_absolute() {
        p.to_path_buf()
    } else {
        base.join(p)
    };
    let mut out = PathBuf::new();
    for c in input.components() {
        match c {
            Component::ParentDir => {
                if !out.pop() || out.as_os_str().is_empty() {
                    return Err(REFUSED);
                }
            }
            Component::CurDir => (),
            x => out.push(x.as_os_str()),
        }
    }
    if !absolute(&out) {
        return Err(REFUSED);
    }
    Ok(out)
}
fn snapshot(input: &CapturedInput) -> OwnedTree {
    match input {
        CapturedInput::Absent(_) => OwnedTree::empty(),
        CapturedInput::Present(t) => OwnedTree {
            files: t
                .entries()
                .map(|(p, b)| (p.to_path_buf(), Zeroizing::new(b.to_vec())))
                .collect(),
            directories: t
                .directories()
                .into_iter()
                .filter(|p| !p.as_os_str().is_empty())
                .map(Path::to_path_buf)
                .collect(),
        },
    }
}
fn capture(
    captures: &mut Vec<RoleCapture>,
    role: Role,
    path: &Path,
    admission: InputRole,
    tree: bool,
) -> Result<()> {
    let base = if tree {
        path
    } else {
        path.parent().ok_or(REFUSED)?
    };
    let input = CapturedTree::capture_optional(
        path,
        base.to_path_buf(),
        admission,
        CaptureLimits::default(),
        tree,
    )
    .map_err(|_| REFUSED)?;
    captures.push(RoleCapture { role, input });
    Ok(())
}
fn capture_private_reference(
    captures: &mut Vec<RoleCapture>,
    role: Role,
    spec: &ReferenceSpec,
    config_root: &Path,
    existing: bool,
    service_uid: u32,
    operator_uid: u32,
) -> Result<()> {
    // A fresh external credential is not copied/chowned during publication.
    // Admit root authority only through the complete root-private held-FD
    // capture, including its ancestry; operator ownership alone never grants
    // a root runtime permission to consume an external credential.
    if !existing
        && !spec.final_path.starts_with(config_root)
        && operator_uid != 0
        && capture(
            captures,
            role,
            &spec.source,
            InputRole::PrivateCredential { expected_uid: 0 },
            false,
        )
        .is_ok()
    {
        return Ok(());
    }
    capture(
        captures,
        role,
        &spec.source,
        InputRole::PrivateCredential {
            expected_uid: if existing { service_uid } else { operator_uid },
        },
        false,
    )
}
fn tree(captures: &[RoleCapture], role: Role) -> Option<&CapturedTree> {
    captures
        .iter()
        .find(|c| c.role == role)
        .and_then(|c| match &c.input {
            CapturedInput::Present(t) => Some(t),
            _ => None,
        })
}
fn one(t: &CapturedTree) -> Result<(&Path, &[u8])> {
    let mut entries = t.entries();
    let first = entries.next().ok_or(REFUSED)?;
    if entries.next().is_some() {
        return Err(REFUSED);
    }
    Ok(first)
}
fn settings(bytes: &[u8]) -> Result<Settings> {
    toml::from_str(std::str::from_utf8(bytes).map_err(|_| REFUSED)?).map_err(|_| REFUSED)
}
fn require_relay(s: &Settings) -> Result<()> {
    crate::profile_auto::validate_auto_relay_auth(s).map_err(|_| REFUSED)
}

/// Before any recursive config-byte capture, require the exact core anchor, or
/// prove a fresh existing directory empty. Never recursively capture an arbitrary
/// supplied HOME simply because caller named it config_root.
#[cfg(target_os = "linux")]
fn empty_existing_directory(path: &Path, uid: u32) -> Result<bool> {
    use std::ffi::{CStr, CString};
    use std::os::unix::ffi::OsStrExt;
    let name = CString::new(path.as_os_str().as_bytes()).map_err(|_| REFUSED)?;
    let fd = unsafe {
        libc::open(
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return if std::io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT) {
            Ok(true)
        } else {
            Err(REFUSED)
        };
    }
    let mut st = std::mem::MaybeUninit::uninit();
    if unsafe { libc::fstat(fd, st.as_mut_ptr()) } != 0 {
        unsafe { libc::close(fd) };
        return Err(REFUSED);
    }
    let st = unsafe { st.assume_init() };
    if (st.st_uid != 0 && st.st_uid != uid) || st.st_mode & 0o022 != 0 {
        unsafe { libc::close(fd) };
        return Err(REFUSED);
    }
    let stream = unsafe { libc::fdopendir(fd) };
    if stream.is_null() {
        unsafe { libc::close(fd) };
        return Err(REFUSED);
    }
    let mut empty = true;
    loop {
        unsafe { *libc::__errno_location() = 0 };
        let e = unsafe { libc::readdir(stream) };
        if e.is_null() {
            if std::io::Error::last_os_error().raw_os_error() != Some(0) {
                unsafe { libc::closedir(stream) };
                return Err(REFUSED);
            }
            break;
        }
        let n = unsafe { CStr::from_ptr((*e).d_name.as_ptr()) };
        if n.to_bytes() != b"." && n.to_bytes() != b".." {
            empty = false;
            break;
        }
    }
    unsafe { libc::closedir(stream) };
    Ok(empty)
}
#[cfg(not(target_os = "linux"))]
fn empty_existing_directory(_: &Path, _: u32) -> Result<bool> {
    Err(REFUSED)
}
fn add_specs(
    specs: &mut Vec<ReferenceSpec>,
    s: &Settings,
    original: &Path,
    final_base: &Path,
    bundle_ca: Option<&Path>,
    masque_ca: Option<&Path>,
) -> Result<()> {
    let mut add = |p: &Path,
                   private: bool,
                   override_source: Option<&Path>,
                   override_final: Option<PathBuf>|
     -> Result<()> {
        let source = override_source
            .map(Path::to_path_buf)
            .map(Ok)
            .unwrap_or_else(|| logical(original, p))?;
        let final_path = override_final
            .map(Ok)
            .unwrap_or_else(|| logical(final_base, p))?;
        if let Some(old) = specs
            .iter()
            .find(|x| x.source == source && x.final_path == final_path)
        {
            if old.private != private {
                return Err(REFUSED);
            }
            return Ok(());
        }
        if specs
            .iter()
            .any(|x| x.final_path == final_path && x.source != source)
        {
            return Err(REFUSED);
        }
        specs.push(ReferenceSpec {
            source,
            final_path,
            private,
        });
        Ok(())
    };
    if let Some(p) = &s.relay.ca_cert {
        let placeholder = p == Path::new("__CLIENT_CA_CERT_PATH__");
        if placeholder && bundle_ca.is_none() {
            return Err(REFUSED);
        }
        add(
            p,
            false,
            if placeholder { bundle_ca } else { None },
            if placeholder {
                Some(final_base.join("ca.pem"))
            } else {
                None
            },
        )?;
    }
    if let Some(p) = &s.relay.masque_ca_cert {
        add(
            p,
            false,
            masque_ca,
            masque_ca.map(|_| final_base.join("masque-ca.pem")),
        )?;
    } else if let Some(p) = masque_ca {
        add(p, false, Some(p), Some(final_base.join("masque-ca.pem")))?;
    }
    if let Some(inner) = &s.relay.inner_tls {
        add(&inner.server_ca, false, None, None)?;
        add(&inner.cert, false, None, None)?;
        add(&inner.key, true, None, None)?;
    }
    if let Some(p) = &s.relay.ech_config_list {
        add(p, false, None, None)?;
    }
    if let Some(bridge) = &s.relay.https_bridge {
        add(&bridge.credential_file, true, None, None)?;
    }
    if let Some(web) = &s.relay.web_response {
        add(&web.credential_file, true, None, None)?;
    }
    Ok(())
}

fn selected_mode(mode: &str) -> Result<SelectedMode> {
    match mode {
        "socks-only" => Ok(SelectedMode::SocksOnly),
        "wide-redirect-safe" => Ok(SelectedMode::WideRedirectSafe),
        "full-wide-tun" => Ok(SelectedMode::FullWideTun),
        _ => Err(REFUSED),
    }
}
#[cfg(target_os = "linux")]
pub(crate) fn prepare(request: Request) -> Result<PreparedInputs> {
    let admin = unsafe { libc::geteuid() };
    if admin != 0 {
        return Err(REFUSED);
    }
    nonoverlap(&[
        &request.config_root,
        &request.state_target,
        &request.metadata_target,
    ])?;
    if let Some(bundle) = &request.bundle {
        nonoverlap(&[
            bundle,
            &request.config_root,
            &request.state_target,
            &request.metadata_target,
        ])?;
    }
    if request.wide_interface.as_ref().is_some_and(|iface| {
        iface.is_empty()
            || iface.len() > 15
            || !iface
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
    }) {
        return Err(REFUSED);
    }
    let service = InputRole::ServiceInput {
        service_uid: request.service_uid,
        administrator_uid: admin,
    };
    let metadata = InputRole::AdministratorMetadata {
        administrator_uid: admin,
    };
    let bundle_role = InputRole::ExplicitBundleData {
        operator_uid: request.operator_uid,
        administrator_uid: admin,
    };
    let anchor = CapturedTree::capture_optional_service_file(
        &request.config_root.join("aegis.toml"),
        &request.config_root,
        request.config_root.clone(),
        service,
        CaptureLimits::default(),
    )
    .map_err(|_| REFUSED)?;
    let existing = matches!(anchor, CapturedInput::Present(_));
    if let CapturedInput::Present(t) = &anchor {
        require_relay(&settings(one(t)?.1)?)?;
    } else if request.bundle.is_none()
        || !empty_existing_directory(&request.config_root, request.service_uid)?
    {
        return Err(REFUSED);
    }
    let mut captures = Vec::new();
    capture(
        &mut captures,
        Role::Config,
        &request.config_root,
        service,
        true,
    )?;
    capture(
        &mut captures,
        Role::StateTarget,
        &request.state_target,
        service,
        true,
    )?;
    capture(
        &mut captures,
        Role::AdministratorMetadata,
        &request.metadata_target,
        metadata,
        true,
    )?;
    // Anchor and full-tree admission both precede planning; mismatch refuses.
    anchor
        .revalidate_original_generation()
        .map_err(|_| REFUSED)?;
    if existing {
        let a = match &anchor {
            CapturedInput::Present(t) => one(t)?.1,
            _ => return Err(REFUSED),
        };
        if tree(&captures, Role::Config)
            .ok_or(REFUSED)?
            .bytes(Path::new("aegis.toml"))
            .map_err(|_| REFUSED)?
            != a
        {
            return Err(REFUSED);
        }
    }
    if !existing {
        if let Some(t) = tree(&captures, Role::Config) {
            if t.entries().next().is_some()
                || t.directories().iter().any(|p| !p.as_os_str().is_empty())
            {
                return Err(REFUSED);
            }
        }
        let bundle = request.bundle.as_ref().ok_or(REFUSED)?;
        for (role, leaf) in [
            (Role::BundleMain, "aegis-client.toml"),
            (Role::BundleCa, "ca.pem"),
            (
                Role::BundleSupplementary,
                "aegis-client-privileged-dns.toml",
            ),
            (Role::BundleMasque, "masque-ca.pem"),
        ] {
            capture(&mut captures, role, &bundle.join(leaf), bundle_role, false)?;
        }
        if tree(&captures, Role::BundleMain).is_none() || tree(&captures, Role::BundleCa).is_none()
        {
            return Err(REFUSED);
        }
    }
    let original_base = if existing {
        request.config_root.clone()
    } else {
        request.bundle.clone().ok_or(REFUSED)?
    };
    let main = Zeroizing::new(
        (if existing {
            tree(&captures, Role::Config)
                .ok_or(REFUSED)?
                .bytes(Path::new("aegis.toml"))
                .map_err(|_| REFUSED)?
        } else {
            one(tree(&captures, Role::BundleMain).ok_or(REFUSED)?)?.1
        })
        .to_vec(),
    );
    let original = settings(&main)?;
    require_relay(&original)?;
    let bundle_ca = if existing {
        None
    } else {
        Some(original_base.join("ca.pem"))
    };
    let masque_ca = request.explicit_masque_ca.clone().or_else(|| {
        if tree(&captures, Role::BundleMasque).is_some() {
            Some(original_base.join("masque-ca.pem"))
        } else {
            None
        }
    });
    let mut specs = Vec::new();
    add_specs(
        &mut specs,
        &original,
        &original_base,
        &request.config_root,
        bundle_ca.as_deref(),
        masque_ca.as_deref(),
    )?;
    if let Some(supp) = tree(&captures, Role::BundleSupplementary) {
        add_specs(
            &mut specs,
            &settings(one(supp)?.1)?,
            &original_base,
            &request.config_root,
            bundle_ca.as_deref(),
            masque_ca.as_deref(),
        )?;
    }
    // Capture every reference independently; key/bridge require singleton private
    // authority even when already included in the generic config tree.
    for (index, spec) in specs.iter().enumerate() {
        let admission = if existing { service } else { bundle_role };
        if spec.private {
            capture_private_reference(
                &mut captures,
                Role::Reference(index),
                spec,
                &request.config_root,
                existing,
                request.service_uid,
                request.operator_uid,
            )?;
        } else if existing
            && spec.source.starts_with(&request.config_root)
            && spec.source != request.config_root
        {
            // Boundary comes from independently supplied sealed target, never
            // from a self-asserted generation record or arbitrary ancestor.
            let input = CapturedTree::capture_optional_service_file(
                &spec.source,
                &request.config_root,
                spec.source.parent().ok_or(REFUSED)?.to_path_buf(),
                admission,
                CaptureLimits::default(),
            )
            .map_err(|_| REFUSED)?;
            captures.push(RoleCapture {
                role: Role::Reference(index),
                input,
            });
        } else {
            capture(
                &mut captures,
                Role::Reference(index),
                &spec.source,
                admission,
                false,
            )?;
        }
        if tree(&captures, Role::Reference(index)).is_none() {
            return Err(REFUSED);
        }
    }
    let raw_doc: toml::Value =
        toml::from_str(std::str::from_utf8(&main).map_err(|_| REFUSED)?).map_err(|_| REFUSED)?;
    let state_spelling = raw_doc
        .get("direct")
        .and_then(|x| x.get("state_path"))
        .and_then(toml::Value::as_str)
        .map(str::to_owned);
    let final_state = request.state_target.join("state.json");
    let state_source = match state_spelling.as_deref() {
        Some(p) if p.starts_with("~/") => Some(logical(
            request.admitted_home.as_deref().ok_or(REFUSED)?,
            Path::new(&p[2..]),
        )?),
        Some(p) => Some(logical(&original_base, Path::new(p))?),
        None => None,
    };
    let relocate = state_spelling
        .as_deref()
        .is_some_and(|p| p.starts_with("~/"))
        || (!existing
            && state_source.as_ref().is_some_and(|p| {
                p.starts_with(&original_base) && !p.starts_with(&request.state_target)
            }));
    if let Some(source) = &state_source {
        capture(&mut captures, Role::StateSource, source, service, false)?;
    }
    // Administrative mode authority is captured before planning, scoped to its
    // distinct metadata role. No config/state filenames collide across roles.
    let previous_profile = tree(&captures, Role::AdministratorMetadata)
        .and_then(|t| t.bytes(Path::new("wide-profile.json")).ok());
    let prior_markers = request.prior_native_markers || existing;
    let plan = crate::profile_auto::plan_captured(
        &main,
        previous_profile,
        prior_markers,
        request.requested_mode.as_deref(),
    )
    .map_err(|_| REFUSED)?;
    let mode = plan
        .get("product_mode")
        .and_then(serde_json::Value::as_str)
        .ok_or(REFUSED)?
        .to_string();
    let selected = selected_mode(&mode)?;
    let options = Options {
        mode: selected,
        input: if existing {
            InputKind::ExistingUpgrade
        } else {
            InputKind::FreshBundle
        },
        final_ca: request.config_root.join("ca.pem"),
        final_state,
        logical_original_base: original_base.clone(),
        logical_final_base: request.config_root.clone(),
        fresh_local_token: if existing {
            None
        } else {
            Some(render::fresh_token())
        },
        masque_server: request.masque_server,
        final_masque_ca: masque_ca
            .as_ref()
            .map(|_| request.config_root.join("masque-ca.pem")),
        captured_bundle_ca: bundle_ca,
        captured_masque_ca: masque_ca,
        captured_previous_state: state_source.clone(),
        relay_pin: request.relay_pin,
        state_path_needs_relocation: relocate,
        wide_interface: request.wide_interface.clone(),
    };
    let mut private = Vec::new();
    for (index, spec) in specs.iter().enumerate() {
        if spec.private {
            let captured = tree(&captures, Role::Reference(index)).ok_or(REFUSED)?;
            let InputRole::PrivateCredential { expected_uid } = captured
                .export_private_generation()
                .map_err(|_| REFUSED)?
                .role()
            else {
                return Err(REFUSED);
            };
            private.push((
                index,
                captured
                    .private_reference(one(captured)?.0, expected_uid)
                    .map_err(|_| REFUSED)?,
            ));
        }
    }
    let mut references = Vec::new();
    for (index, spec) in specs.iter().enumerate() {
        let reference = if spec.private {
            let cap = &private.iter().find(|(i, _)| *i == index).ok_or(REFUSED)?.1;
            CapturedReference::private_credential(&spec.final_path, cap)
        } else {
            CapturedReference::public_certificate(
                &spec.source,
                &spec.final_path,
                one(tree(&captures, Role::Reference(index)).ok_or(REFUSED)?)?.1,
            )
        };
        references.push(reference);
    }
    let supplementary = tree(&captures, Role::BundleSupplementary)
        .map(|t| {
            one(t).map(|(_, b)| Supplementary {
                relative_leaf: Path::new("aegis-client-privileged-dns.toml"),
                captured: b,
            })
        })
        .transpose()?;
    let admitted_state = state_source.as_deref();
    let default_state_leaf = Path::new("state.json");
    let default_state_sink = request.state_target.join(default_state_leaf);
    let default_state_exists =
        tree(&captures, Role::StateTarget).is_some_and(|t| t.bytes(default_state_leaf).is_ok());
    let state_transfer = match (admitted_state, tree(&captures, Role::StateSource)) {
        (Some(source), Some(t)) if source != default_state_sink && !default_state_exists => {
            Some(StateTransfer {
                original_logical_path: source,
                captured: one(t)?.1,
                final_relative_leaf: default_state_leaf,
            })
        }
        _ => None,
    };
    let validators = render::RuntimeCapturedValidators {
        logical_final_base: request.config_root.clone(),
    };
    let mut rendered = render::prepare_render(
        Path::new("aegis.toml"),
        &main,
        supplementary,
        state_transfer,
        &options,
        &ReferenceSet {
            entries: &references,
        },
        &validators,
    )
    .map_err(|_| REFUSED)?;
    let mut passthrough: BTreeMap<PathBuf, Zeroizing<Vec<u8>>> = tree(&captures, Role::Config)
        .map(|t| {
            t.entries()
                .filter(|(p, _)| {
                    *p != Path::new("aegis.toml")
                        && *p != Path::new("aegis-client-privileged-dns.toml")
                })
                .map(|(p, b)| (p.to_path_buf(), Zeroizing::new(b.to_vec())))
                .collect()
        })
        .unwrap_or_default();
    for (index, spec) in specs.iter().enumerate() {
        if let Ok(relative) = spec.final_path.strip_prefix(&request.config_root) {
            if relative == Path::new("aegis.toml")
                || relative == Path::new("aegis-client-privileged-dns.toml")
            {
                return Err(REFUSED);
            }
            passthrough.insert(
                relative.to_path_buf(),
                Zeroizing::new(
                    one(tree(&captures, Role::Reference(index)).ok_or(REFUSED)?)?
                        .1
                        .to_vec(),
                ),
            );
        }
    }
    if existing {
        if let Some(t) = tree(&captures, Role::Config) {
            if let Ok(b) = t.bytes(Path::new("aegis-client-privileged-dns.toml")) {
                passthrough.insert(
                    PathBuf::from("aegis-client-privileged-dns.toml"),
                    Zeroizing::new(b.to_vec()),
                );
            }
        }
    }
    let unchanged = passthrough
        .into_iter()
        .map(|(relative_leaf, bytes)| StagedLeaf {
            relative_leaf,
            bytes,
        })
        .collect();
    rendered
        .include_unchanged_captured_leaves(unchanged)
        .map_err(|_| REFUSED)?;
    let raw: BTreeMap<_, _> = captures
        .iter()
        .map(|c| (c.role, snapshot(&c.input)))
        .collect();
    let mut accepted: BTreeMap<_, _> = raw.iter().map(|(role, t)| (*role, t.copy())).collect();
    let config = accepted.get_mut(&Role::Config).ok_or(REFUSED)?;
    config.files.insert(
        PathBuf::from("aegis.toml"),
        Zeroizing::new(rendered.config.bytes.as_bytes().to_vec()),
    );
    for s in &rendered.supplementary {
        config
            .files
            .insert(s.relative_leaf.clone(), Zeroizing::new(s.bytes.to_vec()));
    }
    let mut before = BTreeMap::new();
    let mut after = BTreeMap::new();
    for (index, spec) in specs.iter().enumerate() {
        before.insert(Role::Reference(index), spec.source.clone());
        after.insert(Role::Reference(index), spec.final_path.clone());
        if let Ok(relative) = spec.final_path.strip_prefix(&request.config_root) {
            config.files.insert(
                relative.to_path_buf(),
                Zeroizing::new(
                    one(tree(&captures, Role::Reference(index)).ok_or(REFUSED)?)?
                        .1
                        .to_vec(),
                ),
            );
        }
    }
    if let Some(s) = &rendered.state_transfer {
        accepted
            .get_mut(&Role::StateTarget)
            .ok_or(REFUSED)?
            .files
            .insert(s.relative_leaf.clone(), Zeroizing::new(s.bytes.to_vec()));
    }
    let metadata_tree = accepted
        .get_mut(&Role::AdministratorMetadata)
        .ok_or(REFUSED)?;
    metadata_tree.files.insert(
        PathBuf::from("auto-install-plan.json"),
        Zeroizing::new(serde_json::to_vec(&plan).map_err(|_| REFUSED)?),
    );
    // Profile header is authority metadata, never a user-editable state tree.
    let mut profile = plan.get("profile").cloned().ok_or(REFUSED)?;
    let fields = profile.as_object_mut().ok_or(REFUSED)?;
    fields.insert(
        "product_mode".into(),
        serde_json::Value::String(mode.clone()),
    );
    fields.insert(
        "interface".into(),
        serde_json::Value::String(request.wide_interface.clone().unwrap_or_default()),
    );
    fields.insert(
        "connectivity_verified".into(),
        serde_json::Value::Bool(false),
    );
    metadata_tree.files.insert(
        PathBuf::from("wide-profile.json"),
        Zeroizing::new(serde_json::to_vec(&profile).map_err(|_| REFUSED)?),
    );
    for owned in accepted.values_mut() {
        // Complete directories for new reference leaf destinations; retain every
        // captured empty directory. File/dir overlap refuses before seal.
        for path in owned.files.keys() {
            let mut parent = path.parent();
            while let Some(p) = parent {
                if p.as_os_str().is_empty() {
                    break;
                }
                owned.directories.insert(p.to_path_buf());
                parent = p.parent();
            }
        }
        if owned.files.keys().any(|p| owned.directories.contains(p)) {
            return Err(REFUSED);
        }
        if owned.files.len() + owned.directories.len() > 1024
            || owned.files.values().map(|b| b.len()).sum::<usize>() > 64 * 1024 * 1024
        {
            return Err(REFUSED);
        }
    }
    let original_generations = captures
        .iter()
        .map(|c| {
            c.input
                .export_private_generation()
                .map(|g| (c.role, g))
                .map_err(|_| REFUSED)
        })
        .collect::<Result<_>>()?;
    for c in &captures {
        c.input
            .revalidate_original_generation()
            .map_err(|_| REFUSED)?;
    }
    let state_mapping = StateMapping {
        original: state_source.clone(),
        final_path: if relocate || state_source.is_none() {
            options.final_state.clone()
        } else {
            state_source.clone().ok_or(REFUSED)?
        },
        relocated: relocate,
    };
    let targets = Targets {
        config: request.config_root,
        state: request.state_target,
        metadata: request.metadata_target,
    };
    let prepared = PreparedInputs {
        targets,
        state_mapping,
        is_upgrade: existing,
        wide_interface: request.wide_interface,
        original_generations,
        raw,
        accepted,
        original_reference_map: before,
        final_reference_map: after,
        plan,
        mode,
        rendered,
        captures,
    };
    prepared.validate_render_mapping()?;
    Ok(prepared)
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn prepare(_: Request) -> Result<PreparedInputs> {
    Err(REFUSED)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(target_os = "linux")]
    fn private_fixture() -> (tempfile::TempDir, ReferenceSpec) {
        use std::os::unix::fs::PermissionsExt;
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let source = root.path().join("device.key");
        std::fs::write(&source, b"synthetic device credential").unwrap();
        std::fs::set_permissions(&source, std::fs::Permissions::from_mode(0o600)).unwrap();
        let spec = ReferenceSpec {
            source: source.clone(),
            final_path: source,
            private: true,
        };
        (root, spec)
    }
    #[cfg(target_os = "linux")]
    fn capture_uid(spec: &ReferenceSpec, config: &Path, existing: bool, uid: u32) -> u32 {
        let mut captures = Vec::new();
        capture_private_reference(
            &mut captures,
            Role::Reference(0),
            spec,
            config,
            existing,
            uid,
            uid,
        )
        .unwrap();
        let captured = tree(&captures, Role::Reference(0)).unwrap();
        let InputRole::PrivateCredential { expected_uid } =
            captured.export_private_generation().unwrap().role()
        else {
            panic!("private role required")
        };
        captured
            .private_reference(Path::new("device.key"), expected_uid)
            .unwrap();
        expected_uid
    }
    #[cfg(target_os = "linux")]
    #[test]
    fn fresh_external_private_owner_is_admitted_before_runtime_binding() {
        let (root, spec) = private_fixture();
        let uid = unsafe { libc::geteuid() };
        // Root execution reproduces the installed sudo operator=501 case.
        // Ordinary CI still executes the operator-owned private capture.
        let operator = if uid == 0 { 501 } else { uid };
        assert_eq!(
            capture_uid(&spec, &root.path().join("config"), false, operator),
            uid
        );
        // Copied fresh credentials and existing service inputs retain their
        // original roles rather than gaining root runtime authority.
        assert_eq!(capture_uid(&spec, root.path(), false, operator), operator);
        assert_eq!(
            capture_uid(&spec, &root.path().join("config"), true, operator),
            operator
        );
        if uid == 0 {
            use std::os::unix::ffi::OsStrExt;
            let name = std::ffi::CString::new(spec.source.as_os_str().as_bytes()).unwrap();
            assert_eq!(unsafe { libc::chown(name.as_ptr(), operator, operator) }, 0);
            assert_eq!(
                capture_uid(&spec, &root.path().join("config"), false, operator),
                operator
            );
            assert_eq!(
                unsafe { libc::chown(name.as_ptr(), operator + 1, operator + 1) },
                0
            );
            assert!(capture_private_reference(
                &mut Vec::new(),
                Role::Reference(0),
                &spec,
                &root.path().join("config"),
                false,
                uid,
                operator
            )
            .is_err());
            // A root key beneath an operator-owned directory must not acquire
            // root runtime authority merely because the leaf is root-owned.
            assert_eq!(unsafe { libc::chown(name.as_ptr(), 0, 0) }, 0);
            let dir = std::ffi::CString::new(root.path().as_os_str().as_bytes()).unwrap();
            assert_eq!(unsafe { libc::chown(dir.as_ptr(), operator, operator) }, 0);
            assert_eq!(
                capture_uid(&spec, &root.path().join("config"), false, operator),
                operator
            );
        }
    }
    #[cfg(target_os = "linux")]
    #[test]
    fn private_capture_preserves_permissions_links_and_generation_refusals() {
        use std::os::unix::fs::PermissionsExt;
        let (root, spec) = private_fixture();
        let uid = unsafe { libc::geteuid() };
        let operator = if uid == 0 { 501 } else { uid };
        let mut captures = Vec::new();
        capture_private_reference(
            &mut captures,
            Role::Reference(0),
            &spec,
            &root.path().join("config"),
            false,
            uid,
            operator,
        )
        .unwrap();
        let captured = tree(&captures, Role::Reference(0)).unwrap();
        let InputRole::PrivateCredential { expected_uid } =
            captured.export_private_generation().unwrap().role()
        else {
            panic!("private role required")
        };
        std::fs::rename(&spec.source, root.path().join("old.key")).unwrap();
        std::fs::write(&spec.source, b"substitution").unwrap();
        std::fs::set_permissions(&spec.source, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(captured
            .private_reference(Path::new("device.key"), expected_uid)
            .is_err());
        std::fs::set_permissions(&spec.source, std::fs::Permissions::from_mode(0o640)).unwrap();
        assert!(capture_private_reference(
            &mut Vec::new(),
            Role::Reference(0),
            &spec,
            &root.path().join("config"),
            false,
            uid,
            operator
        )
        .is_err());
        std::fs::set_permissions(&spec.source, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::hard_link(&spec.source, root.path().join("alias.key")).unwrap();
        assert!(capture_private_reference(
            &mut Vec::new(),
            Role::Reference(0),
            &spec,
            &root.path().join("config"),
            false,
            uid,
            operator
        )
        .is_err());
        std::fs::remove_file(&spec.source).unwrap();
        std::os::unix::fs::symlink(root.path().join("alias.key"), &spec.source).unwrap();
        assert!(capture_private_reference(
            &mut Vec::new(),
            Role::Reference(0),
            &spec,
            &root.path().join("config"),
            false,
            uid,
            operator
        )
        .is_err());
    }
    #[test]
    fn all_three_accepted_modes_are_explicit_and_device_is_outside() {
        assert!(matches!(
            selected_mode("socks-only").unwrap(),
            SelectedMode::SocksOnly
        ));
        assert!(matches!(
            selected_mode("wide-redirect-safe").unwrap(),
            SelectedMode::WideRedirectSafe
        ));
        assert!(matches!(
            selected_mode("full-wide-tun").unwrap(),
            SelectedMode::FullWideTun
        ));
        assert!(selected_mode("device").is_err());
        assert!(selected_mode("full-wide-hybrid-geneva").is_err());
    }
    #[test]
    fn distinct_role_trees_allow_same_state_json_name() {
        let mut roles = BTreeMap::new();
        let mut config = OwnedTree::empty();
        config.files.insert(
            "state.json".into(),
            Zeroizing::new(b"config-held-state".to_vec()),
        );
        let mut state = OwnedTree::empty();
        state.files.insert(
            "state.json".into(),
            Zeroizing::new(b"runtime-state".to_vec()),
        );
        roles.insert(Role::Config, config);
        roles.insert(Role::StateTarget, state);
        assert_ne!(
            roles[&Role::Config].files[Path::new("state.json")].as_slice(),
            roles[&Role::StateTarget].files[Path::new("state.json")].as_slice()
        );
    }
    #[test]
    fn roots_overlap_or_alias_refuse_before_capture() {
        assert!(nonoverlap(&[Path::new("/etc/aegis"), Path::new("/etc/aegis/state")]).is_err());
        assert!(
            nonoverlap(&[Path::new("/home/user/../user"), Path::new("/var/lib/aegis")]).is_err()
        );
        assert!(nonoverlap(&[
            Path::new("/etc/aegis"),
            Path::new("/var/lib/aegis"),
            Path::new("/var/lib/aegis-admin")
        ])
        .is_ok());
    }
    #[test]
    fn copied_owned_tree_keeps_empty_dirs_and_independent_bytes() {
        let mut raw = OwnedTree::empty();
        raw.directories.insert("empty/child".into());
        raw.files
            .insert("aegis.toml".into(), Zeroizing::new(b"captured".to_vec()));
        let mut accepted = raw.copy();
        accepted.files.get_mut(Path::new("aegis.toml")).unwrap()[0] = b'X';
        assert_eq!(raw.files[Path::new("aegis.toml")].as_slice(), b"captured");
        assert!(accepted.directories.contains(Path::new("empty/child")));
    }
}
