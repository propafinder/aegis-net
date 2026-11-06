//! PRIVATE UNAPPLIED PROPOSAL: Linux installer input capture only.
//! Does not stage, plan, authorize identities, publish, stop or restart services.
use std::{
    io,
    path::{Path, PathBuf},
};
use zeroize::Zeroizing;

#[derive(Clone, Copy, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) enum InputRole {
    ServiceInput {
        service_uid: u32,
        administrator_uid: u32,
    },
    AdministratorMetadata {
        administrator_uid: u32,
    },
    ExplicitBundleData {
        operator_uid: u32,
        administrator_uid: u32,
    },
    PrivateCredential {
        expected_uid: u32,
    },
}
impl InputRole {
    fn ancestor(self) -> Self {
        match self {
            Self::ServiceInput {
                administrator_uid, ..
            }
            | Self::AdministratorMetadata { administrator_uid } => {
                Self::AdministratorMetadata { administrator_uid }
            }
            Self::ExplicitBundleData {
                operator_uid,
                administrator_uid,
            } => Self::ExplicitBundleData {
                operator_uid,
                administrator_uid,
            },
            Self::PrivateCredential { expected_uid } => Self::PrivateCredential { expected_uid },
        }
    }
    fn forbidden_file_permissions(self) -> u32 {
        if matches!(self, Self::PrivateCredential { .. }) {
            0o077
        } else {
            0o022
        }
    }
    fn accepts(self, uid: u32) -> bool {
        match self {
            Self::ServiceInput {
                service_uid,
                administrator_uid,
            } => uid == 0 || uid == service_uid || uid == administrator_uid,
            Self::AdministratorMetadata { administrator_uid } => {
                uid == 0 || uid == administrator_uid
            }
            Self::ExplicitBundleData {
                operator_uid,
                administrator_uid,
            } => uid == 0 || uid == operator_uid || uid == administrator_uid,
            Self::PrivateCredential { expected_uid } => uid == 0 || uid == expected_uid,
        }
    }
}
#[derive(Clone, Copy, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CaptureLimits {
    pub(crate) depth: usize,
    pub(crate) files: usize,
    pub(crate) directories: usize,
    pub(crate) file_bytes: u64,
    pub(crate) tree_bytes: u64,
}
impl Default for CaptureLimits {
    fn default() -> Self {
        Self {
            depth: 8,
            files: 1024,
            directories: 1024,
            file_bytes: 16 * 1024 * 1024,
            tree_bytes: 64 * 1024 * 1024,
        }
    }
}
impl CaptureLimits {
    fn validate(self) -> io::Result<()> {
        if self.depth > 8
            || self.files == 0
            || self.files > 1024
            || self.directories == 0
            || self.directories > 1024
            || self.file_bytes == 0
            || self.file_bytes > 16 * 1024 * 1024
            || self.tree_bytes == 0
            || self.tree_bytes > 64 * 1024 * 1024
        {
            return Err(refusal("capture limits refused"));
        }
        Ok(())
    }
}
fn refusal(phase: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, phase)
}
/// Opaque capability created only by a separately admitted private credential capture.
/// No Debug/Serialize; caller cannot construct it from generic path+bytes.
pub(crate) struct PrivateReference<'a> {
    bytes: &'a [u8],
    original_path: &'a Path,
}
impl PrivateReference<'_> {
    pub(crate) fn bytes(&self) -> &[u8] {
        self.bytes
    }
    pub(crate) fn original_path(&self) -> &Path {
        self.original_path
    }
}
struct CapturedFile {
    relative: PathBuf,
    bytes: Zeroizing<Vec<u8>>,
}
/// Deliberately no Debug, Clone or serialization of secret bytes/generation.
pub(crate) struct CapturedTree {
    logical_base: PathBuf,
    files: Vec<CapturedFile>,
    #[cfg(target_os = "linux")]
    state: linux::State,
}
pub(crate) enum CapturedInput {
    Present(CapturedTree),
    Absent(AbsentInput),
}
pub(crate) struct AbsentInput {
    #[cfg(target_os = "linux")]
    state: linux::AbsentState,
}
impl CapturedInput {
    pub(crate) fn export_private_generation(&self) -> io::Result<GenerationRecord> {
        #[cfg(target_os = "linux")]
        {
            Ok(match self {
                Self::Present(t) => t.export_private_generation()?,
                Self::Absent(a) => a.state.record(),
            })
        }
        #[cfg(not(target_os = "linux"))]
        {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "installer capture requires Linux",
            ))
        }
    }
    pub(crate) fn revalidate_original_generation(&self) -> io::Result<()> {
        match self {
            Self::Present(tree) => tree.revalidate_original_generation(),
            Self::Absent(absent) => {
                #[cfg(target_os = "linux")]
                {
                    absent.state.revalidate()
                }
                #[cfg(not(target_os = "linux"))]
                {
                    let _ = absent;
                    Err(io::Error::new(
                        io::ErrorKind::Unsupported,
                        "installer capture requires Linux",
                    ))
                }
            }
        }
    }
}
impl CapturedTree {
    pub(crate) fn capture_optional(
        root: &Path,
        logical_base: PathBuf,
        role: InputRole,
        limits: CaptureLimits,
        tree: bool,
    ) -> io::Result<CapturedInput> {
        limits.validate()?;
        #[cfg(target_os = "linux")]
        {
            if let Some(state) = linux::capture_absence(root, role, limits, tree)? {
                return Ok(CapturedInput::Absent(AbsentInput { state }));
            }
            let captured = if tree {
                Self::capture(root, logical_base, role, limits)?
            } else {
                Self::capture_file(root, logical_base, role, limits)?
            };
            Ok(CapturedInput::Present(captured))
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (root, logical_base, role, tree);
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "installer capture requires Linux",
            ))
        }
    }
    pub(crate) fn capture(
        root: &Path,
        logical_base: PathBuf,
        role: InputRole,
        limits: CaptureLimits,
    ) -> io::Result<Self> {
        limits.validate()?;
        #[cfg(target_os = "linux")]
        {
            let (files, state) = linux::capture(root, role, limits)?;
            Ok(Self {
                logical_base,
                files,
                state,
            })
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (root, logical_base, role);
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "installer capture requires Linux",
            ))
        }
    }
    /// A separately admitted metadata/identity file, not its unrelated siblings.
    pub(crate) fn capture_file(
        file: &Path,
        logical_base: PathBuf,
        role: InputRole,
        limits: CaptureLimits,
    ) -> io::Result<Self> {
        limits.validate()?;
        #[cfg(target_os = "linux")]
        {
            let (files, state) = linux::capture_file(file, role, limits)?;
            Ok(Self {
                logical_base,
                files,
                state,
            })
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (file, logical_base, role);
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "installer capture requires Linux",
            ))
        }
    }
    /// Exact independently supplied service configuration boundary, not arbitrary ancestors.
    pub(crate) fn capture_service_file(
        file: &Path,
        service_root: &Path,
        logical_base: PathBuf,
        role: InputRole,
        limits: CaptureLimits,
    ) -> io::Result<Self> {
        limits.validate()?;
        #[cfg(target_os = "linux")]
        {
            let (files, state) = linux::single_service(file, service_root, role, limits, true)?;
            Ok(Self {
                logical_base,
                files,
                state,
            })
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (file, service_root, logical_base, role);
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "installer capture requires Linux",
            ))
        }
    }
    pub(crate) fn capture_optional_service_file(
        file: &Path,
        service_root: &Path,
        logical_base: PathBuf,
        role: InputRole,
        limits: CaptureLimits,
    ) -> io::Result<CapturedInput> {
        limits.validate()?;
        #[cfg(target_os = "linux")]
        {
            linux::service_boundary(file, service_root, role)?;
            if let Some(state) = linux::capture_service_absence(file, service_root, role, limits)? {
                return Ok(CapturedInput::Absent(AbsentInput { state }));
            }
            Ok(CapturedInput::Present(Self::capture_service_file(
                file,
                service_root,
                logical_base,
                role,
                limits,
            )?))
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (file, service_root, logical_base, role);
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "installer capture requires Linux",
            ))
        }
    }
    pub(crate) fn export_private_generation(&self) -> io::Result<GenerationRecord> {
        #[cfg(target_os = "linux")]
        {
            Ok(self.state.record())
        }
        #[cfg(not(target_os = "linux"))]
        {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "installer capture requires Linux",
            ))
        }
    }
    pub(crate) fn private_reference(
        &self,
        relative: &Path,
        expected_uid: u32,
    ) -> io::Result<PrivateReference<'_>> {
        #[cfg(target_os = "linux")]
        {
            if !matches!(self.state.role,InputRole::PrivateCredential{expected_uid:uid} if uid==expected_uid)
                || self.state.kind != 1
            {
                return Err(refusal("separate private credential admission required"));
            }
            self.revalidate_original_generation()?;
            Ok(PrivateReference {
                bytes: self.bytes(relative)?,
                original_path: &self.state.source,
            })
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (relative, expected_uid);
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "installer capture requires Linux",
            ))
        }
    }
    /// Includes the root as empty relative path and preserves empty captured directories.
    pub(crate) fn directories(&self) -> Vec<&Path> {
        #[cfg(target_os = "linux")]
        {
            self.state.directory_paths()
        }
        #[cfg(not(target_os = "linux"))]
        {
            Vec::new()
        }
    }
    pub(crate) fn logical_base(&self) -> &Path {
        &self.logical_base
    }
    pub(crate) fn bytes(&self, relative: &Path) -> io::Result<&[u8]> {
        if relative.is_absolute()
            || relative
                .components()
                .any(|c| !matches!(c, std::path::Component::Normal(_)))
        {
            return Err(refusal("capture relative reference refused"));
        }
        self.files
            .iter()
            .find(|f| f.relative == relative)
            .map(|f| f.bytes.as_slice())
            .ok_or_else(|| refusal("capture reference absent"))
    }
    pub(crate) fn entries(&self) -> impl Iterator<Item = (&Path, &[u8])> {
        self.files
            .iter()
            .map(|f| (f.relative.as_path(), f.bytes.as_slice()))
    }
    /// Metadata/namespace only: never reads a second selected byte generation.
    pub(crate) fn revalidate_original_generation(&self) -> io::Result<()> {
        #[cfg(target_os = "linux")]
        {
            self.state.revalidate()
        }
        #[cfg(not(target_os = "linux"))]
        {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "installer capture requires Linux",
            ))
        }
    }
}
/// Independent ordinary-user CLI reader: bounded chosen file only, not installer transaction authority.
/// No Debug/Serialize, generation export, sibling capture or side-effecting special-file open.
pub(crate) struct StandaloneConfig {
    captured: CapturedTree,
    filename: PathBuf,
}
impl StandaloneConfig {
    pub(crate) fn text(&self) -> io::Result<&str> {
        #[cfg(target_os = "linux")]
        if self.captured.state.kind != 1
            || self.captured.logical_base().join(&self.filename) != self.captured.state.source
        {
            return Err(refusal("standalone singleton logical binding refused"));
        }
        std::str::from_utf8(self.captured.bytes(&self.filename)?)
            .map_err(|_| refusal("standalone config UTF-8 refused"))
    }
    #[cfg(test)]
    pub(crate) fn logical_base(&self) -> &Path {
        self.captured.logical_base()
    }
    pub(crate) fn revalidate(&self) -> io::Result<()> {
        self.captured.revalidate_original_generation()
    }
}
pub(crate) fn read_standalone_config(path: &Path) -> io::Result<StandaloneConfig> {
    #[cfg(target_os = "linux")]
    {
        let cwd = if path.is_absolute() {
            PathBuf::from("/")
        } else {
            std::env::current_dir()
                .map_err(|_| refusal("standalone logical working directory refused"))?
        };
        linux::standalone(path, &cwd)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = path;
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "automatic installation requires Linux",
        ))
    }
}
/// Private metadata only: caller MUST authenticate root-owned sealed stage first.
/// No public JSON authority, byte recapture, secret serialization or Debug.
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct GenerationRecord {
    schema: u32,
    source: PathBuf,
    role: InputRole,
    limits: CaptureLimits,
    kind: u8,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    service_root: Option<PathBuf>,
    #[cfg(target_os = "linux")]
    bindings: Vec<(bool, linux::Generation, Vec<u8>)>,
    #[cfg(target_os = "linux")]
    directories: Vec<(linux::Generation, Vec<Vec<u8>>)>,
}
impl GenerationRecord {
    // Metadata accessors only: admission still requires root-private stage ownership
    // and caller comparison with its independently expected roots/roles/kind/limits.
    pub(crate) fn original_source(&self) -> &Path {
        &self.source
    }
    pub(crate) fn service_root(&self) -> Option<&Path> {
        self.service_root.as_deref()
    }
    pub(crate) fn role(&self) -> InputRole {
        self.role
    }
    pub(crate) fn limits(&self) -> CaptureLimits {
        self.limits
    }
    pub(crate) fn kind(&self) -> u8 {
        self.kind
    }
}
/// Root-owned sealed-stage bytes, not arbitrary caller memory. Construct only after
/// Store admitted its root-owned sealed header and checked original generation,
/// reference index/path/role mapping and this expected hash from that private header.
/// This capture additionally enforces actual held-FD root/private stage custody.
/// No public constructor from raw bytes, Debug or secret hash output.
/// Implemented by the bridge Store's held, already admitted root-private sealed
/// header guard. This is a trusted Rust component contract, not public JSON authority.
/// Capture never accepts an unvalidated caller-provided hash as stage authority.
pub(crate) trait SealedStageAuthority {
    fn revalidate(&self) -> io::Result<()>;
    #[cfg(all(test, target_os = "linux"))]
    fn admitted_stage_sha256(&self, stage_path: &Path) -> io::Result<[u8; 32]>;
    #[cfg(all(test, target_os = "linux"))]
    fn admit_private_original(
        &self,
        stage_path: &Path,
        original: &GenerationRecord,
        expected_uid: u32,
    ) -> io::Result<()>;
}
/// Borrowed proof from the SAME Store's accepted-render/own-publication receipt.
/// Bridge validates its concrete phase, exact original sealed reference identity,
/// UID/role/source mapping and committed/current owned publication generation.
/// Only originals retired by that Store's own publication are admissible here;
/// external/current references still require live GenerationGuard admission.
/// This is not a public JSON flag or a stand-alone manifest authority.
#[cfg(all(test, target_os = "linux"))]
pub(crate) trait OwnPublicationAuthority {
    fn source_stage_authority(&self) -> &dyn SealedStageAuthority;
    fn admit_retired_private_original(
        &self,
        stage_path: &Path,
        original: &GenerationRecord,
        expected_uid: u32,
    ) -> io::Result<()>;
}
/// Distinct post-publication path. No reopen/byte reread of legitimately retired
/// original input; the Store's typed accepted-publication proof owns that transition.
#[cfg(all(test, target_os = "linux"))]
pub(crate) fn private_reference_after_own_publication<'a>(
    stage: &'a AdmittedStageBytes<'_>,
    original: &'a GenerationRecord,
    expected_uid: u32,
    publication: &dyn OwnPublicationAuthority,
) -> io::Result<PrivateReference<'a>> {
    #[cfg(target_os = "linux")]
    {
        if original.kind != 1
            || !matches!(original.role,InputRole::PrivateCredential{expected_uid:uid} if uid==expected_uid)
        {
            return Err(refusal("retired private credential role refused"));
        }
        // Reject a proof from a different held Store/header authority, even if
        // caller-supplied path/role strings happen to match. No authority IDs output.
        if !std::ptr::eq(stage.authority, publication.source_stage_authority()) {
            return Err(refusal("publication Store authority mismatch"));
        }
        stage.authority.revalidate()?;
        publication.admit_retired_private_original(
            &stage.captured.state.source,
            original,
            expected_uid,
        )?;
        stage.captured.state.require_private_stage_parent()?;
        stage.captured.revalidate_original_generation()?;
        stage.authority.revalidate()?;
        Ok(PrivateReference {
            bytes: stage.captured.bytes(&stage.filename)?,
            original_path: &original.source,
        })
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (stage, original, expected_uid, publication);
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "installer capture requires Linux",
        ))
    }
}
#[cfg(all(test, target_os = "linux"))]
pub(crate) struct AdmittedStageBytes<'a> {
    captured: CapturedTree,
    filename: PathBuf,
    authority: &'a dyn SealedStageAuthority,
}
#[cfg(all(test, target_os = "linux"))]
impl<'a> AdmittedStageBytes<'a> {
    pub(crate) fn admit_root_stage_file(
        path: &Path,
        authority: &'a dyn SealedStageAuthority,
    ) -> io::Result<Self> {
        #[cfg(target_os = "linux")]
        {
            if unsafe { libc::geteuid() } != 0 {
                return Err(refusal("root sealed-stage authority required"));
            }
            authority.revalidate()?;
            let expected_private_sha256 = authority.admitted_stage_sha256(path)?;
            let parent = path
                .parent()
                .ok_or_else(|| refusal("sealed-stage parent refused"))?;
            let filename = PathBuf::from(
                path.file_name()
                    .ok_or_else(|| refusal("sealed-stage file refused"))?,
            );
            let limits = CaptureLimits {
                file_bytes: 4 * 1024 * 1024,
                tree_bytes: 4 * 1024 * 1024,
                files: 1,
                ..CaptureLimits::default()
            };
            let captured = CapturedTree::capture_file(
                path,
                parent.into(),
                InputRole::PrivateCredential { expected_uid: 0 },
                limits,
            )?;
            captured.state.require_private_stage_parent()?;
            use sha2::Digest;
            let actual: [u8; 32] = sha2::Sha256::digest(captured.bytes(&filename)?).into();
            if actual != expected_private_sha256 {
                return Err(refusal("sealed-stage bytes binding refused"));
            }
            captured.revalidate_original_generation()?;
            authority.revalidate()?;
            Ok(Self {
                captured,
                filename,
                authority,
            })
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (path, authority);
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "installer capture requires Linux",
            ))
        }
    }
}
pub(crate) struct GenerationGuard {
    #[cfg(target_os = "linux")]
    input: CapturedInput,
}
impl GenerationGuard {
    /// Original metadata is revalidated; only the already sealed staged byte
    /// generation is read. Caller Store must bind both to one admitted header.
    #[cfg(all(test, target_os = "linux"))]
    pub(crate) fn private_reference_from_admitted_stage<'a>(
        &'a self,
        stage: &'a AdmittedStageBytes<'_>,
        expected_uid: u32,
    ) -> io::Result<PrivateReference<'a>> {
        #[cfg(target_os = "linux")]
        {
            let CapturedInput::Present(original) = &self.input else {
                return Err(refusal("private credential original absent"));
            };
            if original.state.kind != 1
                || !matches!(original.state.role,InputRole::PrivateCredential{expected_uid:uid} if uid==expected_uid)
            {
                return Err(refusal("separate private credential generation required"));
            }
            self.revalidate()?;
            stage.authority.revalidate()?;
            stage.authority.admit_private_original(
                &stage.captured.state.source,
                &original.export_private_generation()?,
                expected_uid,
            )?;
            stage.captured.state.require_private_stage_parent()?;
            stage.captured.revalidate_original_generation()?;
            Ok(PrivateReference {
                bytes: stage.captured.bytes(&stage.filename)?,
                original_path: &original.state.source,
            })
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (stage, expected_uid);
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "installer capture requires Linux",
            ))
        }
    }
    pub(crate) fn revalidate(&self) -> io::Result<()> {
        #[cfg(target_os = "linux")]
        {
            self.input.revalidate_original_generation()
        }
        #[cfg(not(target_os = "linux"))]
        {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "installer capture requires Linux",
            ))
        }
    }

    /// The runtime account binding seals these digests separately from the
    /// metadata-only GenerationRecord. Read the already pinned singleton FD;
    /// a fresh pathname read could select a different byte generation.
    pub(crate) fn revalidate_singleton_sha256(&self, expected: &[u8; 32]) -> io::Result<()> {
        #[cfg(target_os = "linux")]
        {
            let CapturedInput::Present(tree) = &self.input else {
                return Err(refusal("account singleton absent"));
            };
            tree.state.revalidate_singleton_sha256(expected)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = expected;
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "installer capture requires Linux",
            ))
        }
    }
}
pub(crate) fn reopen_generation(record: &GenerationRecord) -> io::Result<GenerationGuard> {
    if record.service_root.is_some() {
        return Err(refusal("independent service boundary required"));
    }
    reopen_bound_generation(record, None)
}
pub(crate) fn reopen_service_generation(
    record: &GenerationRecord,
    expected_service_root: &Path,
) -> io::Result<GenerationGuard> {
    if record.service_root.as_deref() != Some(expected_service_root)
        || !matches!(record.role, InputRole::ServiceInput { .. })
        || !matches!(record.kind, 1 | 3)
    {
        return Err(refusal("service generation boundary mismatch"));
    }
    reopen_bound_generation(record, Some(expected_service_root))
}
fn reopen_bound_generation(
    record: &GenerationRecord,
    expected_service_root: Option<&Path>,
) -> io::Result<GenerationGuard> {
    record.limits.validate()?;
    if record.service_root.as_deref() != expected_service_root {
        return Err(refusal("service generation boundary mismatch"));
    }
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::ffi::OsStrExt;
        if record.schema != 1
            || record.source.as_os_str().as_bytes().len() > 4096
            || record.bindings.len() > 4096
            || record.directories.len() > 1024
            || record.bindings.iter().any(|(_, _, n)| n.len() > 255)
            || record
                .directories
                .iter()
                .any(|(_, ns)| ns.len() > 2048 || ns.iter().any(|n| n.len() > 255))
        {
            return Err(refusal("private generation bounds refused"));
        }
        let input = match record.kind {
            0 | 1 => {
                let (files, state) = if let Some(root) = expected_service_root {
                    linux::single_service(&record.source, root, record.role, record.limits, false)?
                } else {
                    linux::metadata_only(
                        &record.source,
                        record.role,
                        record.limits,
                        record.kind == 0,
                    )?
                };
                CapturedInput::Present(CapturedTree {
                    logical_base: PathBuf::new(),
                    files,
                    state,
                })
            }
            2 | 3 => {
                let state = if let Some(root) = expected_service_root {
                    linux::capture_service_absence(
                        &record.source,
                        root,
                        record.role,
                        record.limits,
                    )?
                } else {
                    linux::capture_absence(
                        &record.source,
                        record.role,
                        record.limits,
                        record.kind == 2,
                    )?
                };
                let state = state.ok_or_else(|| refusal("absent input appeared"))?;
                CapturedInput::Absent(AbsentInput { state })
            }
            _ => return Err(refusal("private generation kind refused")),
        };
        let actual = input.export_private_generation()?;
        if actual.service_root != record.service_root
            || actual.kind != record.kind
            || actual.bindings != record.bindings
            || actual.directories != record.directories
        {
            return Err(refusal("private source generation changed"));
        }
        Ok(GenerationGuard { input })
    }
    #[cfg(not(target_os = "linux"))]
    {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "installer capture requires Linux",
        ))
    }
}
#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use std::{
        ffi::{CStr, CString, OsString},
        fs::{File, Metadata},
        io::Read,
        os::{
            fd::{AsRawFd, FromRawFd},
            unix::{
                ffi::{OsStrExt, OsStringExt},
                fs::MetadataExt,
            },
        },
    };
    #[derive(Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
    pub(super) struct Generation {
        dev: u64,
        ino: u64,
        mode: u32,
        uid: u32,
        gid: u32,
        links: u64,
        len: u64,
        modified: (i64, i64),
        changed: (i64, i64),
    }
    impl Generation {
        fn ancestor(mut self) -> Self {
            self.links = 0;
            self.len = 0;
            self.modified = (0, 0);
            self.changed = (0, 0);
            self
        }
        fn from(m: &Metadata) -> Self {
            Self {
                dev: m.dev(),
                ino: m.ino(),
                mode: m.mode(),
                uid: m.uid(),
                gid: m.gid(),
                links: m.nlink(),
                len: m.len(),
                modified: (m.mtime(), m.mtime_nsec()),
                changed: (m.ctime(), m.ctime_nsec()),
            }
        }
        fn binding(self, other: Self) -> bool {
            self.dev == other.dev
                && self.ino == other.ino
                && self.mode == other.mode
                && self.uid == other.uid
                && self.gid == other.gid
        }
    }
    fn generation(fd: &File) -> io::Result<Generation> {
        fd.metadata()
            .map(|m| Generation::from(&m))
            .map_err(|_| refusal("capture descriptor metadata refused"))
    }
    fn name(bytes: &[u8]) -> io::Result<CString> {
        CString::new(bytes).map_err(|_| refusal("capture component refused"))
    }
    fn open_at(parent: &File, leaf: &CStr, flags: i32) -> io::Result<File> {
        let fd = unsafe {
            libc::openat(
                parent.as_raw_fd(),
                leaf.as_ptr(),
                flags | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(refusal("capture no-follow open refused"));
        }
        Ok(unsafe { File::from_raw_fd(fd) })
    }
    fn directory_ok(g: Generation, role: InputRole, ancestor: bool) -> io::Result<()> {
        let root_sticky_ancestor = ancestor && g.uid == 0 && g.mode & libc::S_ISVTX != 0;
        if g.mode & libc::S_IFMT != libc::S_IFDIR
            || !role.accepts(g.uid)
            || (g.mode & 0o022 != 0 && !root_sticky_ancestor)
        {
            return Err(refusal("capture directory role refused"));
        }
        Ok(())
    }
    struct Binding {
        parent: File,
        leaf: CString,
        descriptor: File,
        expected: Generation,
        full: bool,
    }
    impl Binding {
        fn revalidate(&self) -> io::Result<()> {
            let current = generation(&self.descriptor)?;
            let named = open_at(&self.parent, &self.leaf, libc::O_PATH | libc::O_NONBLOCK)?;
            let fresh = generation(&named)?;
            if (self.full && (current != self.expected || fresh != self.expected))
                || (!self.full
                    && (!self.expected.binding(current) || !self.expected.binding(fresh)))
            {
                return Err(refusal("capture generation changed"));
            }
            Ok(())
        }
    }
    struct Directory {
        descriptor: File,
        expected: Generation,
        members: Vec<OsString>,
        relative: PathBuf,
    }
    fn members(fd: &File) -> io::Result<Vec<OsString>> {
        // openat(".") gives independent directory cursor while retaining admission.
        let dot = name(b".")?;
        let copy = open_at(fd, &dot, libc::O_RDONLY | libc::O_DIRECTORY)?;
        let raw = std::os::fd::IntoRawFd::into_raw_fd(copy);
        let stream = unsafe { libc::fdopendir(raw) };
        if stream.is_null() {
            unsafe {
                libc::close(raw);
            }
            return Err(refusal("capture directory enumeration refused"));
        }
        struct Close(*mut libc::DIR);
        impl Drop for Close {
            fn drop(&mut self) {
                unsafe {
                    libc::closedir(self.0);
                }
            }
        }
        let guard = Close(stream);
        let mut result = Vec::new();
        loop {
            unsafe {
                *libc::__errno_location() = 0;
            }
            let entry = unsafe { libc::readdir(guard.0) };
            if entry.is_null() {
                if unsafe { *libc::__errno_location() } != 0 {
                    return Err(refusal("capture directory enumeration refused"));
                }
                break;
            }
            let bytes = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
            if bytes == b"." || bytes == b".." {
                continue;
            }
            if result.len() >= 2048 {
                return Err(refusal("capture membership limit refused"));
            }
            result.push(OsString::from_vec(bytes.to_vec()));
        }
        result.sort();
        Ok(result)
    }
    pub(super) struct State {
        bindings: Vec<Binding>,
        directories: Vec<Directory>,
        proc_fd: File,
        pub(super) source: PathBuf,
        pub(super) role: InputRole,
        limits: CaptureLimits,
        pub(super) kind: u8,
        service_root: Option<PathBuf>,
        read_bytes: bool,
        seen_files: usize,
    }
    impl State {
        #[cfg(all(test, target_os = "linux"))]
        pub(super) fn require_private_stage_parent(&self) -> io::Result<()> {
            if self.kind != 1
                || !matches!(self.role, InputRole::PrivateCredential { expected_uid: 0 })
            {
                return Err(refusal("root sealed-stage singleton required"));
            }
            let parent = &self
                .bindings
                .last()
                .ok_or_else(|| refusal("sealed-stage parent witness absent"))?
                .parent;
            let g = generation(parent)?;
            if g.mode & libc::S_IFMT != libc::S_IFDIR || g.uid != 0 || g.mode & 0o077 != 0 {
                return Err(refusal("root sealed-stage parent custody refused"));
            }
            Ok(())
        }
        pub(super) fn directory_paths(&self) -> Vec<&Path> {
            self.directories
                .iter()
                .map(|d| d.relative.as_path())
                .collect()
        }
        pub(super) fn record(&self) -> GenerationRecord {
            GenerationRecord {
                schema: 1,
                source: self.source.clone(),
                role: self.role,
                limits: self.limits,
                kind: self.kind,
                service_root: self.service_root.clone(),
                bindings: self
                    .bindings
                    .iter()
                    .map(|b| {
                        (
                            b.full,
                            if b.full {
                                b.expected
                            } else {
                                b.expected.ancestor()
                            },
                            b.leaf.as_bytes().to_vec(),
                        )
                    })
                    .collect(),
                directories: self
                    .directories
                    .iter()
                    .map(|d| {
                        (
                            d.expected,
                            d.members.iter().map(|n| n.as_bytes().to_vec()).collect(),
                        )
                    })
                    .collect(),
            }
        }
        pub(super) fn revalidate(&self) -> io::Result<()> {
            for b in &self.bindings {
                b.revalidate()?;
            }
            for d in &self.directories {
                if generation(&d.descriptor)? != d.expected || members(&d.descriptor)? != d.members
                {
                    return Err(refusal("capture directory generation changed"));
                }
            }
            Ok(())
        }

        pub(super) fn revalidate_singleton_sha256(&self, expected: &[u8; 32]) -> io::Result<()> {
            use sha2::Digest;
            if self.kind != 1
                || self.service_root.is_some()
                || self.seen_files != 1
                || !matches!(
                    self.role,
                    InputRole::PrivateCredential { .. } | InputRole::AdministratorMetadata { .. }
                )
            {
                return Err(refusal("account singleton digest role refused"));
            }
            self.revalidate()?;
            let bound = self
                .bindings
                .last()
                .filter(|b| b.full)
                .ok_or_else(|| refusal("account singleton descriptor absent"))?;
            let original = generation(&bound.descriptor)?;
            if original != bound.expected
                || original.len > self.limits.file_bytes
                || original.len > self.limits.tree_bytes
            {
                return Err(refusal("account singleton generation changed"));
            }
            let mut reader = pinned_reader(&self.proc_fd, &bound.descriptor)?;
            if generation(&reader)? != original {
                return Err(refusal("account singleton pinned identity changed"));
            }
            let mut bytes = Zeroizing::new(Vec::new());
            reader
                .by_ref()
                .take(self.limits.file_bytes + 1)
                .read_to_end(&mut bytes)
                .map_err(|_| refusal("account singleton bounded read refused"))?;
            if bytes.len() as u64 != original.len
                || generation(&reader)? != original
                || generation(&bound.descriptor)? != original
            {
                return Err(refusal("account singleton changed during read"));
            }
            let actual: [u8; 32] = sha2::Sha256::digest(bytes.as_slice()).into();
            if &actual != expected {
                return Err(refusal("account singleton content changed"));
            }
            self.revalidate()
        }
    }
    fn trusted_proc_fd() -> io::Result<File> {
        let proc_name = name(b"/proc")?;
        let raw = unsafe {
            libc::open(
                proc_name.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if raw < 0 {
            return Err(refusal("capture trusted procfs unavailable"));
        }
        let proc = unsafe { File::from_raw_fd(raw) };
        let g = generation(&proc)?;
        let mut fs = std::mem::MaybeUninit::<libc::statfs>::uninit();
        if g.uid != 0
            || g.mode & 0o022 != 0
            || unsafe { libc::fstatfs(proc.as_raw_fd(), fs.as_mut_ptr()) } != 0
            || unsafe { fs.assume_init() }.f_type != 0x9fa0
        {
            return Err(refusal("capture trusted procfs refused"));
        }
        // The only followed link is the verified kernel procfs self magic link,
        // never any input component. Its held descriptor anchors current-process fd entries.
        let self_name = name(b"self")?;
        let raw = unsafe {
            libc::openat(
                proc.as_raw_fd(),
                self_name.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
            )
        };
        if raw < 0 {
            return Err(refusal("capture procfs self refused"));
        }
        let current = unsafe { File::from_raw_fd(raw) };
        let fd_name = name(b"fd")?;
        let fd = open_at(&current, &fd_name, libc::O_RDONLY | libc::O_DIRECTORY)?;
        let mut fs = std::mem::MaybeUninit::<libc::statfs>::uninit();
        if unsafe { libc::fstatfs(fd.as_raw_fd(), fs.as_mut_ptr()) } != 0
            || unsafe { fs.assume_init() }.f_type != 0x9fa0
        {
            return Err(refusal("capture procfs descriptor refused"));
        }
        Ok(fd)
    }
    fn pinned_reader(proc_fd: &File, pinned: &File) -> io::Result<File> {
        let number = name(pinned.as_raw_fd().to_string().as_bytes())?;
        // Magic fd entry is admitted only under the held verified kernel procfs.
        let raw = unsafe {
            libc::openat(
                proc_fd.as_raw_fd(),
                number.as_ptr(),
                libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NONBLOCK,
            )
        };
        if raw < 0 {
            return Err(refusal("capture pinned read refused"));
        }
        Ok(unsafe { File::from_raw_fd(raw) })
    }
    pub(super) struct AbsentState {
        bindings: Vec<Binding>,
        parent: File,
        leaf: CString,
        expected: Generation,
        source: PathBuf,
        role: InputRole,
        limits: CaptureLimits,
        kind: u8,
        service_root: Option<PathBuf>,
    }
    fn absent(parent: &File, leaf: &CStr) -> io::Result<bool> {
        let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
        if unsafe {
            libc::fstatat(
                parent.as_raw_fd(),
                leaf.as_ptr(),
                stat.as_mut_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        } == 0
        {
            return Ok(false);
        }
        if io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT) {
            Ok(true)
        } else {
            Err(refusal("capture absence observation refused"))
        }
    }
    impl AbsentState {
        pub(super) fn record(&self) -> GenerationRecord {
            let mut b: Vec<_> = self
                .bindings
                .iter()
                .map(|x| (false, x.expected.ancestor(), x.leaf.as_bytes().to_vec()))
                .collect();
            b.push((
                false,
                self.expected.ancestor(),
                self.leaf.as_bytes().to_vec(),
            ));
            GenerationRecord {
                schema: 1,
                source: self.source.clone(),
                role: self.role,
                limits: self.limits,
                kind: self.kind,
                service_root: self.service_root.clone(),
                bindings: b,
                directories: Vec::new(),
            }
        }
        pub(super) fn revalidate(&self) -> io::Result<()> {
            for b in &self.bindings {
                b.revalidate()?;
            }
            if !self.expected.binding(generation(&self.parent)?)
                || !absent(&self.parent, &self.leaf)?
            {
                return Err(refusal("capture absent generation changed"));
            }
            Ok(())
        }
    }
    pub(super) fn capture_absence(
        path: &Path,
        role: InputRole,
        limits: CaptureLimits,
        tree: bool,
    ) -> io::Result<Option<AbsentState>> {
        capture_absence_bound(path, role, limits, tree, None)
    }
    pub(super) fn capture_service_absence(
        path: &Path,
        root: &Path,
        role: InputRole,
        limits: CaptureLimits,
    ) -> io::Result<Option<AbsentState>> {
        service_boundary(path, root, role)?;
        capture_absence_bound(path, role, limits, false, Some(root))
    }
    fn capture_absence_bound(
        path: &Path,
        role: InputRole,
        limits: CaptureLimits,
        tree: bool,
        service_root: Option<&Path>,
    ) -> io::Result<Option<AbsentState>> {
        strict_path(path)?;
        let parts: Vec<_> = path
            .components()
            .filter_map(|c| match c {
                std::path::Component::Normal(n) => Some(n.to_os_string()),
                _ => None,
            })
            .collect();
        if parts.is_empty() {
            return Err(refusal("capture absent target refused"));
        }
        let slash = name(b"/")?;
        let raw = unsafe {
            libc::open(
                slash.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if raw < 0 {
            return Err(refusal("capture absence root refused"));
        }
        let mut fd = unsafe { File::from_raw_fd(raw) };
        let mut bindings = Vec::new();
        directory_ok(generation(&fd)?, role.ancestor(), true)?;
        let mut traversed = PathBuf::from("/");
        for (index, component) in parts.iter().enumerate() {
            let leaf = name(component.as_bytes())?;
            if absent(&fd, &leaf)? {
                let suffix = &parts[index..];
                if suffix.len() > limits.depth || suffix.iter().any(|n| n.as_bytes().len() > 255) {
                    return Err(refusal("capture absent suffix limit refused"));
                }
                let expected = generation(&fd)?;
                let state = AbsentState {
                    bindings,
                    parent: fd,
                    leaf,
                    expected,
                    source: path.into(),
                    role,
                    limits,
                    kind: if tree { 2 } else { 3 },
                    service_root: service_root.map(Path::to_path_buf),
                };
                state.revalidate()?;
                return Ok(Some(state));
            }
            if index + 1 == parts.len() {
                return Ok(None);
            }
            let child = open_at(&fd, &leaf, libc::O_RDONLY | libc::O_DIRECTORY)?;
            let expected = generation(&child)?;
            traversed.push(component);
            let inside = service_root.is_some_and(|root| traversed.starts_with(root));
            let policy = if inside { role } else { role.ancestor() };
            directory_ok(expected, policy, !inside)?;
            bindings.push(Binding {
                parent: fd
                    .try_clone()
                    .map_err(|_| refusal("capture handle limit refused"))?,
                leaf,
                descriptor: child
                    .try_clone()
                    .map_err(|_| refusal("capture handle limit refused"))?,
                expected,
                full: false,
            });
            fd = child;
        }
        Err(refusal("capture absent traversal refused"))
    }
    fn strict_path(path: &Path) -> io::Result<()> {
        if !path.is_absolute()
            || path == Path::new("/")
            || path
                .as_os_str()
                .as_bytes()
                .split(|b| *b == b'/')
                .any(|c| c == b"." || c == b"..")
        {
            return Err(refusal("capture absolute nonalias input required"));
        }
        Ok(())
    }
    fn root_chain(root: &Path, role: InputRole) -> io::Result<(File, Vec<Binding>)> {
        strict_path(root)?;
        let slash = name(b"/")?;
        let raw = unsafe {
            libc::open(
                slash.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if raw < 0 {
            return Err(refusal("capture root open refused"));
        }
        let mut fd = unsafe { File::from_raw_fd(raw) };
        let mut chain = Vec::new();
        directory_ok(generation(&fd)?, role, true)?;
        let components: Vec<_> = root
            .components()
            .filter(|c| !matches!(c, std::path::Component::RootDir))
            .collect();
        for (index, part) in components.iter().enumerate() {
            let std::path::Component::Normal(part) = part else {
                if matches!(part, std::path::Component::RootDir) {
                    continue;
                }
                return Err(refusal("capture root component refused"));
            };
            let leaf = name(part.as_bytes())?;
            let child = open_at(&fd, &leaf, libc::O_RDONLY | libc::O_DIRECTORY)?;
            let g = generation(&child)?;
            directory_ok(
                g,
                if index + 1 == components.len() {
                    role
                } else {
                    role.ancestor()
                },
                index + 1 != components.len(),
            )?;
            chain.push(Binding {
                parent: fd
                    .try_clone()
                    .map_err(|_| refusal("capture handle limit refused"))?,
                leaf,
                descriptor: child
                    .try_clone()
                    .map_err(|_| refusal("capture handle limit refused"))?,
                expected: g,
                full: false,
            });
            fd = child;
        }
        directory_ok(generation(&fd)?, role, false)?;
        Ok((fd, chain))
    }
    // The independent descriptor, role and byte/depth counters remain explicit.
    // Bundling them solely to shorten argv would obscure custody checks.
    #[allow(clippy::too_many_arguments)]
    fn walk(
        fd: File,
        relative: PathBuf,
        depth: usize,
        role: InputRole,
        limits: CaptureLimits,
        state: &mut State,
        files: &mut Vec<CapturedFile>,
        total: &mut u64,
    ) -> io::Result<()> {
        if depth > limits.depth || state.directories.len() >= limits.directories {
            return Err(refusal("capture tree depth/directory limit refused"));
        }
        let before = generation(&fd)?;
        directory_ok(before, role, false)?;
        let names = members(&fd)?;
        state.directories.push(Directory {
            descriptor: fd
                .try_clone()
                .map_err(|_| refusal("capture handle limit refused"))?,
            expected: before,
            members: names.clone(),
            relative: relative.clone(),
        });
        for member in names {
            let leaf = name(member.as_bytes())?;
            // O_PATH creates a non-I/O handle even if raced to a FIFO/device/link.
            let pinned = open_at(&fd, &leaf, libc::O_PATH | libc::O_NONBLOCK)?;
            let g = generation(&pinned)?;
            let path = relative.join(&member);
            match g.mode & libc::S_IFMT {
                libc::S_IFDIR => {
                    directory_ok(g, role, false)?;
                    let directory = open_at(&fd, &leaf, libc::O_RDONLY | libc::O_DIRECTORY)?;
                    if generation(&directory)? != g {
                        return Err(refusal("capture directory substitution refused"));
                    }
                    state.bindings.push(Binding {
                        parent: fd
                            .try_clone()
                            .map_err(|_| refusal("capture handle limit refused"))?,
                        leaf,
                        descriptor: pinned,
                        expected: g,
                        full: true,
                    });
                    walk(
                        directory,
                        path,
                        depth + 1,
                        role,
                        limits,
                        state,
                        files,
                        total,
                    )?;
                }
                libc::S_IFREG => {
                    if !role.accepts(g.uid)
                        || g.mode & role.forbidden_file_permissions() != 0
                        || g.links != 1
                        || g.len > limits.file_bytes
                        || state.seen_files >= limits.files
                    {
                        return Err(refusal("capture file role/limit refused"));
                    }
                    *total = total
                        .checked_add(g.len)
                        .filter(|n| *n <= limits.tree_bytes)
                        .ok_or_else(|| refusal("capture tree bytes refused"))?;
                    state.seen_files += 1;
                    if state.read_bytes {
                        // Linux kernel procfs is an explicit dependency for reopening a
                        // pinned regular O_PATH handle; input symlinks are never followed.
                        let mut reader = pinned_reader(&state.proc_fd, &pinned)?;
                        if generation(&reader)? != g {
                            return Err(refusal("capture pinned identity refused"));
                        }
                        let mut bytes = Zeroizing::new(Vec::new());
                        reader
                            .by_ref()
                            .take(limits.file_bytes + 1)
                            .read_to_end(&mut bytes)
                            .map_err(|_| refusal("capture bounded read refused"))?;
                        if bytes.len() as u64 != g.len
                            || generation(&reader)? != g
                            || generation(&pinned)? != g
                        {
                            return Err(refusal("capture file changed during read"));
                        }
                        files.push(CapturedFile {
                            relative: path,
                            bytes,
                        });
                    }
                    state.bindings.push(Binding {
                        parent: fd
                            .try_clone()
                            .map_err(|_| refusal("capture handle limit refused"))?,
                        leaf,
                        descriptor: pinned,
                        expected: g,
                        full: true,
                    });
                }
                _ => return Err(refusal("capture special/link input refused")),
            }
        }
        if generation(&fd)? != before
            || members(&fd)?
                != state
                    .directories
                    .iter()
                    .find(|d| d.expected.dev == before.dev && d.expected.ino == before.ino)
                    .ok_or_else(|| refusal("capture directory witness absent"))?
                    .members
        {
            return Err(refusal("capture directory changed during walk"));
        }
        Ok(())
    }
    // CLI aliases are traversed through held no-follow descriptors, not lexically
    // collapsed before checking their real directory components. This preserves
    // ./ and ../ semantics but refuses symlink/../ aliases rather than following them.
    pub(super) fn standalone(path: &Path, cwd: &Path) -> io::Result<StandaloneConfig> {
        let bytes = path.as_os_str().as_bytes();
        if bytes.is_empty() || bytes.len() > 4096 || bytes.ends_with(b"/") {
            return Err(refusal("standalone chosen file refused"));
        }
        let parts: Vec<_> = bytes
            .split(|b| *b == b'/')
            .filter(|c| !c.is_empty())
            .collect();
        if parts.len() > 128 {
            return Err(refusal("standalone path component limit refused"));
        }
        let (last, ancestors) = parts
            .split_last()
            .ok_or_else(|| refusal("standalone chosen file refused"))?;
        if *last == b"." || *last == b".." {
            return Err(refusal("standalone chosen file refused"));
        }
        let uid = unsafe { libc::geteuid() };
        let role = InputRole::ExplicitBundleData {
            operator_uid: uid,
            administrator_uid: uid,
        };
        let (mut directory, mut bindings, mut logical) = if path.is_absolute() {
            let slash = name(b"/")?;
            let raw = unsafe {
                libc::open(
                    slash.as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )
            };
            if raw < 0 {
                return Err(refusal("standalone root refused"));
            }
            (
                unsafe { File::from_raw_fd(raw) },
                Vec::new(),
                PathBuf::from("/"),
            )
        } else {
            if cwd == Path::new("/") {
                let slash = name(b"/")?;
                let raw = unsafe {
                    libc::open(
                        slash.as_ptr(),
                        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                    )
                };
                if raw < 0 {
                    return Err(refusal("standalone root refused"));
                }
                (
                    unsafe { File::from_raw_fd(raw) },
                    Vec::new(),
                    PathBuf::from("/"),
                )
            } else {
                let (fd, chain) = root_chain(cwd, role)?;
                (fd, chain, cwd.to_path_buf())
            }
        };
        directory_ok(generation(&directory)?, role, true)?;
        for part in ancestors {
            if *part == b"." {
                continue;
            }
            let leaf = name(part)?;
            let child = open_at(&directory, &leaf, libc::O_RDONLY | libc::O_DIRECTORY)?;
            let g = generation(&child)?;
            directory_ok(g, role, true)?;
            bindings.push(Binding {
                parent: directory
                    .try_clone()
                    .map_err(|_| refusal("capture handle limit refused"))?,
                leaf,
                descriptor: child
                    .try_clone()
                    .map_err(|_| refusal("capture handle limit refused"))?,
                expected: g,
                full: false,
            });
            directory = child;
            if *part == b".." {
                logical.pop();
                if logical.as_os_str().is_empty() {
                    logical.push("/");
                }
            } else {
                logical.push(OsString::from_vec(part.to_vec()));
            }
        }
        let leaf = name(last)?;
        let pinned = open_at(&directory, &leaf, libc::O_PATH | libc::O_NONBLOCK)?;
        let g = generation(&pinned)?;
        const MAX: u64 = 4 * 1024 * 1024;
        if g.mode & libc::S_IFMT != libc::S_IFREG
            || !role.accepts(g.uid)
            || g.mode & 0o022 != 0
            || g.links != 1
            || g.len > MAX
        {
            return Err(refusal("standalone bounded regular file refused"));
        }
        let proc_fd = trusted_proc_fd()?;
        let mut reader = pinned_reader(&proc_fd, &pinned)?;
        if generation(&reader)? != g {
            return Err(refusal("standalone pinned identity refused"));
        }
        let mut captured = Zeroizing::new(Vec::new());
        reader
            .by_ref()
            .take(MAX + 1)
            .read_to_end(&mut captured)
            .map_err(|_| refusal("standalone bounded read refused"))?;
        if captured.len() as u64 != g.len || generation(&reader)? != g || generation(&pinned)? != g
        {
            return Err(refusal("standalone changed during read"));
        }
        let filename = PathBuf::from(OsString::from_vec(last.to_vec()));
        let source = logical.join(&filename);
        bindings.push(Binding {
            parent: directory,
            leaf,
            descriptor: pinned,
            expected: g,
            full: true,
        });
        let limits = CaptureLimits {
            depth: 8,
            files: 1,
            directories: 1,
            file_bytes: MAX,
            tree_bytes: MAX,
        };
        let state = State {
            bindings,
            directories: Vec::new(),
            proc_fd,
            source,
            role,
            limits,
            kind: 1,
            service_root: None,
            read_bytes: true,
            seen_files: 1,
        };
        state.revalidate()?;
        Ok(StandaloneConfig {
            captured: CapturedTree {
                logical_base: logical,
                files: vec![CapturedFile {
                    relative: filename.clone(),
                    bytes: captured,
                }],
                state,
            },
            filename,
        })
    }
    pub(super) fn service_boundary(file: &Path, root: &Path, role: InputRole) -> io::Result<()> {
        strict_path(file)?;
        strict_path(root)?;
        if !matches!(role, InputRole::ServiceInput { .. })
            || !file.starts_with(root)
            || file == root
            || root.as_os_str().as_bytes().len() > 4096
        {
            return Err(refusal("explicit service root boundary refused"));
        }
        Ok(())
    }
    fn service_parent_chain(
        parent: &Path,
        root: &Path,
        role: InputRole,
    ) -> io::Result<(File, Vec<Binding>)> {
        let (mut fd, mut bindings) = root_chain(root, role)?;
        let suffix = parent
            .strip_prefix(root)
            .map_err(|_| refusal("service parent outside boundary"))?;
        for component in suffix.components() {
            let std::path::Component::Normal(part) = component else {
                return Err(refusal("service parent component refused"));
            };
            let leaf = name(part.as_bytes())?;
            let child = open_at(&fd, &leaf, libc::O_RDONLY | libc::O_DIRECTORY)?;
            let expected = generation(&child)?;
            directory_ok(expected, role, false)?;
            bindings.push(Binding {
                parent: fd
                    .try_clone()
                    .map_err(|_| refusal("capture handle limit refused"))?,
                leaf,
                descriptor: child
                    .try_clone()
                    .map_err(|_| refusal("capture handle limit refused"))?,
                expected,
                full: false,
            });
            fd = child;
        }
        Ok((fd, bindings))
    }
    pub(super) fn capture_file(
        file: &Path,
        role: InputRole,
        limits: CaptureLimits,
    ) -> io::Result<(Vec<CapturedFile>, State)> {
        single(file, role, limits, true)
    }
    fn single(
        file: &Path,
        role: InputRole,
        limits: CaptureLimits,
        read_bytes: bool,
    ) -> io::Result<(Vec<CapturedFile>, State)> {
        single_bound(file, role, limits, read_bytes, None)
    }
    pub(super) fn single_service(
        file: &Path,
        root: &Path,
        role: InputRole,
        limits: CaptureLimits,
        read_bytes: bool,
    ) -> io::Result<(Vec<CapturedFile>, State)> {
        service_boundary(file, root, role)?;
        single_bound(file, role, limits, read_bytes, Some(root))
    }
    fn single_bound(
        file: &Path,
        role: InputRole,
        limits: CaptureLimits,
        read_bytes: bool,
        service_root: Option<&Path>,
    ) -> io::Result<(Vec<CapturedFile>, State)> {
        strict_path(file)?;
        let parent = file
            .parent()
            .ok_or_else(|| refusal("capture file parent refused"))?;
        let filename = file
            .file_name()
            .ok_or_else(|| refusal("capture file component refused"))?;
        let (directory, mut bindings) = if parent == Path::new("/") {
            let slash = name(b"/")?;
            let raw = unsafe {
                libc::open(
                    slash.as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )
            };
            if raw < 0 {
                return Err(refusal("capture singleton root parent refused"));
            }
            let fd = unsafe { File::from_raw_fd(raw) };
            directory_ok(generation(&fd)?, role.ancestor(), true)?;
            (fd, Vec::new())
        } else {
            if let Some(root) = service_root {
                service_parent_chain(parent, root, role)?
            } else {
                root_chain(parent, role.ancestor())?
            }
        };
        let leaf = name(filename.as_bytes())?;
        let pinned = open_at(&directory, &leaf, libc::O_PATH | libc::O_NONBLOCK)?;
        let g = generation(&pinned)?;
        if g.mode & libc::S_IFMT != libc::S_IFREG
            || !role.accepts(g.uid)
            || g.mode & role.forbidden_file_permissions() != 0
            || g.links != 1
            || g.len > limits.file_bytes
            || g.len > limits.tree_bytes
        {
            return Err(refusal("capture single file role/limit refused"));
        }
        let proc_fd = trusted_proc_fd()?;
        let mut files = Vec::new();
        if read_bytes {
            let mut reader = pinned_reader(&proc_fd, &pinned)?;
            if generation(&reader)? != g {
                return Err(refusal("capture pinned identity refused"));
            }
            let mut bytes = Zeroizing::new(Vec::new());
            reader
                .by_ref()
                .take(limits.file_bytes + 1)
                .read_to_end(&mut bytes)
                .map_err(|_| refusal("capture bounded read refused"))?;
            if bytes.len() as u64 != g.len || generation(&reader)? != g || generation(&pinned)? != g
            {
                return Err(refusal("capture file changed during read"));
            }
            files.push(CapturedFile {
                relative: PathBuf::from(filename),
                bytes,
            });
        }
        bindings.push(Binding {
            parent: directory,
            leaf,
            descriptor: pinned,
            expected: g,
            full: true,
        });
        let state = State {
            bindings,
            directories: Vec::new(),
            proc_fd,
            source: file.into(),
            role,
            limits,
            kind: 1,
            service_root: service_root.map(Path::to_path_buf),
            read_bytes,
            seen_files: 1,
        };
        state.revalidate()?;
        Ok((files, state))
    }
    pub(super) fn metadata_only(
        root: &Path,
        role: InputRole,
        limits: CaptureLimits,
        is_tree: bool,
    ) -> io::Result<(Vec<CapturedFile>, State)> {
        if is_tree {
            tree(root, role, limits, false)
        } else {
            single(root, role, limits, false)
        }
    }
    pub(super) fn capture(
        root: &Path,
        role: InputRole,
        limits: CaptureLimits,
    ) -> io::Result<(Vec<CapturedFile>, State)> {
        tree(root, role, limits, true)
    }
    fn tree(
        root: &Path,
        role: InputRole,
        limits: CaptureLimits,
        read_bytes: bool,
    ) -> io::Result<(Vec<CapturedFile>, State)> {
        let (fd, bindings) = root_chain(root, role)?;
        let mut state = State {
            bindings,
            directories: Vec::new(),
            proc_fd: trusted_proc_fd()?,
            source: root.into(),
            role,
            limits,
            kind: 0,
            service_root: None,
            read_bytes,
            seen_files: 0,
        };
        let mut files = Vec::new();
        let mut total = 0;
        walk(
            fd,
            PathBuf::new(),
            0,
            role,
            limits,
            &mut state,
            &mut files,
            &mut total,
        )?;
        state.revalidate()?;
        Ok((files, state))
    }
}
#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use std::{
        fs,
        os::unix::fs::{symlink, PermissionsExt},
    };
    fn role() -> InputRole {
        InputRole::ServiceInput {
            service_uid: unsafe { libc::geteuid() },
            administrator_uid: unsafe { libc::geteuid() },
        }
    }
    fn fixture() -> tempfile::TempDir {
        let d = tempfile::tempdir().unwrap();
        fs::set_permissions(d.path(), fs::Permissions::from_mode(0o700)).unwrap();
        d
    }
    fn cap(d: &Path) -> io::Result<CapturedTree> {
        CapturedTree::capture(
            d,
            PathBuf::from("/original/logical/base"),
            role(),
            CaptureLimits::default(),
        )
    }
    #[test]
    fn post_publication_capability_requires_same_authority_and_exact_retirement_proof() {
        let d = fixture();
        let uid = unsafe { libc::geteuid() };
        let original = d.path().join("key");
        fs::write(&original, b"synthetic").unwrap();
        fs::set_permissions(&original, fs::Permissions::from_mode(0o600)).unwrap();
        let c = CapturedTree::capture_file(
            &original,
            d.path().into(),
            InputRole::PrivateCredential { expected_uid: uid },
            CaptureLimits::default(),
        )
        .unwrap();
        let record = c.export_private_generation().unwrap();
        drop(c);
        let dir = d.path().join("stage");
        fs::create_dir(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        let bytes = dir.join("bytes");
        fs::write(&bytes, b"synthetic").unwrap();
        fs::set_permissions(&bytes, fs::Permissions::from_mode(0o600)).unwrap();
        struct FixtureStore {
            stage: PathBuf,
            original: PathBuf,
        }
        impl SealedStageAuthority for FixtureStore {
            fn revalidate(&self) -> io::Result<()> {
                Ok(())
            }
            fn admitted_stage_sha256(&self, p: &Path) -> io::Result<[u8; 32]> {
                use sha2::Digest;
                if p != self.stage {
                    return Err(refusal("fixture map refused"));
                }
                Ok(sha2::Sha256::digest(b"synthetic").into())
            }
            fn admit_private_original(
                &self,
                _: &Path,
                _: &GenerationRecord,
                _: u32,
            ) -> io::Result<()> {
                Err(refusal(
                    "live admission deliberately unavailable after retirement",
                ))
            }
        }
        struct FixturePublication<'a> {
            store: &'a FixtureStore,
            accepted: bool,
        }
        impl OwnPublicationAuthority for FixturePublication<'_> {
            fn source_stage_authority(&self) -> &dyn SealedStageAuthority {
                self.store
            }
            fn admit_retired_private_original(
                &self,
                p: &Path,
                r: &GenerationRecord,
                u: u32,
            ) -> io::Result<()> {
                if !self.accepted
                    || p != self.store.stage
                    || r.original_source() != self.store.original
                    || u != 0
                {
                    return Err(refusal("fixture retirement proof refused"));
                }
                Ok(())
            }
        }
        let store = FixtureStore {
            stage: bytes.clone(),
            original: original.clone(),
        };
        if uid != 0 {
            assert!(AdmittedStageBytes::admit_root_stage_file(&bytes, &store).is_err());
            return;
        }
        let stage = AdmittedStageBytes::admit_root_stage_file(&bytes, &store).unwrap();
        fs::rename(&original, d.path().join("retired")).unwrap();
        fs::write(&original, b"new generation").unwrap();
        assert!(reopen_generation(&record).is_err());
        let denied = FixturePublication {
            store: &store,
            accepted: false,
        };
        assert!(private_reference_after_own_publication(&stage, &record, 0, &denied).is_err());
        let other = FixtureStore {
            stage: bytes.clone(),
            original: original.clone(),
        };
        let other_proof = FixturePublication {
            store: &other,
            accepted: true,
        };
        assert!(private_reference_after_own_publication(&stage, &record, 0, &other_proof).is_err());
        let accepted = FixturePublication {
            store: &store,
            accepted: true,
        };
        let cap = private_reference_after_own_publication(&stage, &record, 0, &accepted).unwrap();
        assert!(cap.bytes() == b"synthetic");
        assert!(cap.original_path() == original);
        assert!(private_reference_after_own_publication(&stage, &record, 1, &accepted).is_err());
        fs::write(&bytes, b"changed").unwrap();
        assert!(private_reference_after_own_publication(&stage, &record, 0, &accepted).is_err());
    }
    #[test]
    fn durable_private_stage_credential_has_original_path_and_refuses_wrong_binding() {
        let d = fixture();
        let original = d.path().join("original-key");
        fs::write(&original, b"synthetic-key").unwrap();
        fs::set_permissions(&original, fs::Permissions::from_mode(0o600)).unwrap();
        let uid = unsafe { libc::geteuid() };
        let c = CapturedTree::capture_file(
            &original,
            d.path().into(),
            InputRole::PrivateCredential { expected_uid: uid },
            CaptureLimits::default(),
        )
        .unwrap();
        let record = c.export_private_generation().unwrap();
        drop(c);
        let guard = reopen_generation(&record).unwrap();
        let stage = d.path().join("stage");
        fs::create_dir(&stage).unwrap();
        fs::set_permissions(&stage, fs::Permissions::from_mode(0o700)).unwrap();
        let bytes = stage.join("bytes");
        fs::write(&bytes, b"synthetic-key").unwrap();
        fs::set_permissions(&bytes, fs::Permissions::from_mode(0o600)).unwrap();
        use sha2::Digest;
        let hash: [u8; 32] = sha2::Sha256::digest(b"synthetic-key").into();
        struct FixtureAuthority {
            hash: [u8; 32],
            stage: PathBuf,
            original: PathBuf,
        }
        impl SealedStageAuthority for FixtureAuthority {
            fn revalidate(&self) -> io::Result<()> {
                Ok(())
            }
            fn admitted_stage_sha256(&self, p: &Path) -> io::Result<[u8; 32]> {
                if p != self.stage {
                    return Err(refusal("fixture stage map mismatch"));
                }
                Ok(self.hash)
            }
            fn admit_private_original(
                &self,
                p: &Path,
                r: &GenerationRecord,
                uid: u32,
            ) -> io::Result<()> {
                if p != self.stage || r.original_source() != self.original || uid != 0 {
                    return Err(refusal("fixture original map mismatch"));
                }
                Ok(())
            }
        }
        let authority = FixtureAuthority {
            hash,
            stage: bytes.clone(),
            original: original.clone(),
        };
        let wrong = FixtureAuthority {
            hash: [0; 32],
            stage: bytes.clone(),
            original: original.clone(),
        };
        if uid != 0 {
            assert!(AdmittedStageBytes::admit_root_stage_file(&bytes, &authority).is_err());
            return;
        }
        assert!(AdmittedStageBytes::admit_root_stage_file(&bytes, &wrong).is_err());
        let admitted = AdmittedStageBytes::admit_root_stage_file(&bytes, &authority).unwrap();
        let cap = guard
            .private_reference_from_admitted_stage(&admitted, uid)
            .unwrap();
        assert!(cap.bytes() == b"synthetic-key");
        assert!(cap.original_path() == original);
        assert!(guard
            .private_reference_from_admitted_stage(&admitted, 1)
            .is_err());
        fs::write(&bytes, b"changed").unwrap();
        assert!(guard
            .private_reference_from_admitted_stage(&admitted, uid)
            .is_err());
    }
    #[test]
    fn empty_directory_membership_is_preserved_for_sealed_publication() {
        let d = fixture();
        fs::create_dir(d.path().join("empty")).unwrap();
        let c = cap(d.path()).unwrap();
        let dirs = c.directories();
        assert!(dirs.contains(&Path::new("")));
        assert!(dirs.contains(&Path::new("empty")));
        assert!(c.entries().count() == 0);
        c.revalidate_original_generation().unwrap();
    }
    #[test]
    fn standalone_relative_aliases_and_logical_base_are_bound_without_siblings() {
        let d = fixture();
        let sub = d.path().join("space directory");
        fs::create_dir(&sub).unwrap();
        fs::write(d.path().join("config.toml"), b"synthetic = true\n").unwrap();
        fs::write(d.path().join("unrelated"), b"not selected").unwrap();
        for input in [
            "config.toml",
            "./config.toml",
            "space directory/../config.toml",
        ] {
            let c = linux::standalone(Path::new(input), d.path()).unwrap();
            assert!(c.text().unwrap() == "synthetic = true\n");
            assert!(c.logical_base() == d.path());
            assert!(c.captured.entries().count() == 1);
            c.revalidate().unwrap();
        }
        let c = linux::standalone(Path::new("../config.toml"), &sub).unwrap();
        assert!(c.logical_base() == d.path());
        symlink(&sub, d.path().join("alias")).unwrap();
        assert!(linux::standalone(Path::new("alias/../config.toml"), d.path()).is_err());
    }
    #[test]
    fn standalone_fifo_oversize_invalid_utf8_and_mutation_refuse() {
        let d = fixture();
        let leaf = d.path().join("config");
        fs::write(&leaf, b"valid").unwrap();
        let c = linux::standalone(Path::new("config"), d.path()).unwrap();
        fs::write(&leaf, b"changed").unwrap();
        assert!(c.revalidate().is_err());
        assert!(c.text().unwrap() == "valid");
        fs::write(&leaf, [0xff]).unwrap();
        assert!(linux::standalone(Path::new("config"), d.path())
            .unwrap()
            .text()
            .is_err());
        fs::write(&leaf, vec![0u8; 4 * 1024 * 1024 + 1]).unwrap();
        assert!(linux::standalone(Path::new("config"), d.path()).is_err());
        fs::remove_file(&leaf).unwrap();
        use std::os::unix::ffi::OsStrExt;
        let n = std::ffi::CString::new(leaf.as_os_str().as_bytes()).unwrap();
        assert!(unsafe { libc::mkfifo(n.as_ptr(), 0o600) } == 0);
        assert!(linux::standalone(Path::new("config"), d.path()).is_err());
    }
    #[test]
    fn private_credentials_require_separate_role_and_owner_only_permissions() {
        let d = fixture();
        let leaf = d.path().join("key");
        fs::write(&leaf, b"synthetic credential").unwrap();
        fs::set_permissions(&leaf, fs::Permissions::from_mode(0o600)).unwrap();
        let uid = unsafe { libc::geteuid() };
        let generic =
            CapturedTree::capture_file(&leaf, d.path().into(), role(), CaptureLimits::default())
                .unwrap();
        assert!(generic.private_reference(Path::new("key"), uid).is_err());
        let secret = CapturedTree::capture_file(
            &leaf,
            d.path().into(),
            InputRole::PrivateCredential { expected_uid: uid },
            CaptureLimits::default(),
        )
        .unwrap();
        assert!(
            secret
                .private_reference(Path::new("key"), uid)
                .unwrap()
                .bytes()
                == b"synthetic credential"
        );
        assert!(
            secret
                .private_reference(Path::new("key"), uid)
                .unwrap()
                .original_path()
                == leaf
        );
        assert!(secret
            .private_reference(Path::new("key"), uid.wrapping_add(1))
            .is_err());
        fs::set_permissions(&leaf, fs::Permissions::from_mode(0o640)).unwrap();
        assert!(secret.private_reference(Path::new("key"), uid).is_err());
        assert!(CapturedTree::capture_file(
            &leaf,
            d.path().into(),
            InputRole::PrivateCredential { expected_uid: uid },
            CaptureLimits::default()
        )
        .is_err());
    }
    #[test]
    fn actual_nested_bytes_and_logical_base_survive_without_recapture() {
        let d = fixture();
        fs::create_dir(d.path().join("nested")).unwrap();
        fs::write(
            d.path().join("nested/config.toml"),
            b"synthetic = 'private'\n",
        )
        .unwrap();
        let c = cap(d.path()).unwrap();
        assert!(c.bytes(Path::new("nested/config.toml")).unwrap() == b"synthetic = 'private'\n");
        assert!(c.logical_base() == Path::new("/original/logical/base"));
        c.revalidate_original_generation().unwrap();
        assert!(c.entries().count() == 1);
    }
    #[test]
    fn actual_symlink_hardlink_and_fifo_refuse() {
        for kind in 0..3 {
            let d = fixture();
            let original = d.path().join("original");
            fs::write(&original, b"synthetic").unwrap();
            let leaf = d.path().join("bad");
            match kind {
                0 => symlink(&original, &leaf).unwrap(),
                1 => fs::hard_link(&original, &leaf).unwrap(),
                _ => {
                    use std::os::unix::ffi::OsStrExt;
                    let n = std::ffi::CString::new(leaf.as_os_str().as_bytes()).unwrap();
                    assert!(unsafe { libc::mkfifo(n.as_ptr(), 0o600) } == 0);
                }
            }
            assert!(cap(d.path()).is_err());
        }
    }
    #[test]
    fn substitution_and_membership_changes_refuse_but_memory_stays_original() {
        let d = fixture();
        let leaf = d.path().join("config.toml");
        fs::write(&leaf, b"one").unwrap();
        let c = cap(d.path()).unwrap();
        fs::rename(&leaf, d.path().join("old")).unwrap();
        fs::write(&leaf, b"two").unwrap();
        assert!(c.revalidate_original_generation().is_err());
        assert!(c.bytes(Path::new("config.toml")).unwrap() == b"one");
    }
    #[test]
    fn in_place_modification_and_parent_replacement_refuse() {
        let d = fixture();
        let parent = d.path().join("root");
        fs::create_dir(&parent).unwrap();
        fs::write(parent.join("config"), b"one").unwrap();
        let c = cap(&parent).unwrap();
        fs::write(parent.join("config"), b"other bytes").unwrap();
        assert!(c.revalidate_original_generation().is_err());
        let c = cap(&parent).unwrap();
        fs::rename(&parent, d.path().join("retained")).unwrap();
        fs::create_dir(&parent).unwrap();
        assert!(c.revalidate_original_generation().is_err());
    }
    #[test]
    fn actual_modes_and_file_tree_depth_limits_refuse() {
        let d = fixture();
        fs::write(d.path().join("config"), b"1234").unwrap();
        let mut l = CaptureLimits {
            file_bytes: 3,
            ..CaptureLimits::default()
        };
        assert!(CapturedTree::capture(d.path(), d.path().into(), role(), l).is_err());
        l.file_bytes = 4;
        l.tree_bytes = 3;
        assert!(CapturedTree::capture(d.path(), d.path().into(), role(), l).is_err());
        fs::set_permissions(d.path().join("config"), fs::Permissions::from_mode(0o666)).unwrap();
        assert!(cap(d.path()).is_err());
        fs::remove_file(d.path().join("config")).unwrap();
        let mut n = d.path().to_path_buf();
        for _ in 0..9 {
            n = n.join("next");
            fs::create_dir(&n).unwrap();
        }
        assert!(cap(d.path()).is_err());
    }
    #[test]
    fn single_file_admission_does_not_recapture_or_copy_siblings() {
        let d = fixture();
        let leaf = d.path().join("metadata.json");
        fs::write(&leaf, b"synthetic metadata").unwrap();
        fs::write(d.path().join("unselected"), b"unrelated").unwrap();
        let c =
            CapturedTree::capture_file(&leaf, d.path().into(), role(), CaptureLimits::default())
                .unwrap();
        assert!(c.entries().count() == 1);
        fs::write(d.path().join("another"), b"sibling").unwrap();
        c.revalidate_original_generation().unwrap();
        fs::write(&leaf, b"replacement").unwrap();
        assert!(c.revalidate_original_generation().is_err());
        assert!(c.bytes(Path::new("metadata.json")).unwrap() == b"synthetic metadata");
    }
    #[test]
    fn absent_multiple_ancestors_bind_nearest_existing_and_refuse_creation() {
        let d = fixture();
        let target = d.path().join("missing/deeper/config");
        let c = CapturedTree::capture_optional(
            &target,
            d.path().into(),
            role(),
            CaptureLimits::default(),
            false,
        )
        .unwrap();
        assert!(matches!(&c, CapturedInput::Absent(_)));
        let record = c.export_private_generation().unwrap();
        drop(c);
        let guard = reopen_generation(&record).unwrap();
        guard.revalidate().unwrap();
        fs::create_dir(d.path().join("missing")).unwrap();
        assert!(guard.revalidate().is_err());
        assert!(reopen_generation(&record).is_err());
    }
    #[test]
    fn absent_generation_then_creation_refuses() {
        let d = fixture();
        let missing = d.path().join("metadata");
        let c = CapturedTree::capture_optional(
            &missing,
            d.path().into(),
            role(),
            CaptureLimits::default(),
            false,
        )
        .unwrap();
        assert!(matches!(&c, CapturedInput::Absent(_)));
        c.revalidate_original_generation().unwrap();
        fs::write(&missing, b"appeared").unwrap();
        assert!(c.revalidate_original_generation().is_err());
    }
    #[test]
    fn membership_addition_and_root_alias_refuse() {
        let d = fixture();
        let c = cap(d.path()).unwrap();
        fs::write(d.path().join("added"), b"new").unwrap();
        assert!(c.revalidate_original_generation().is_err());
        assert!(cap(Path::new("/")).is_err());
        assert!(cap(&d.path().join(".")).is_err());
    }
    #[test]
    fn service_owned_ancestor_does_not_gain_admin_custody() {
        let d = fixture();
        let nested = d.path().join("input");
        fs::create_dir(&nested).unwrap();
        let uid = unsafe { libc::geteuid() };
        if uid != 0 {
            let r = InputRole::ServiceInput {
                service_uid: uid,
                administrator_uid: uid + 1,
            };
            assert!(
                CapturedTree::capture(&nested, nested.clone(), r, CaptureLimits::default())
                    .is_err()
            );
        }
    }
    #[test]
    fn exported_generation_reopens_metadata_only_and_refuses_substitution() {
        let d = fixture();
        fs::write(d.path().join("config"), b"private synthetic").unwrap();
        let c = cap(d.path()).unwrap();
        let record = c.export_private_generation().unwrap();
        drop(c);
        let guard = reopen_generation(&record).unwrap();
        guard.revalidate().unwrap();
        fs::write(d.path().join("config"), b"other bytes").unwrap();
        assert!(guard.revalidate().is_err());
        assert!(reopen_generation(&record).is_err());
    }
    #[test]
    fn metadata_role_does_not_gain_service_authority() {
        let admin = InputRole::AdministratorMetadata {
            administrator_uid: 1001,
        };
        let input = InputRole::ServiceInput {
            service_uid: 1002,
            administrator_uid: 1001,
        };
        assert!(!admin.accepts(1002));
        assert!(input.accepts(1002));
        assert!(!input.accepts(1003));
        let d = fixture();
        fs::write(d.path().join("a"), b"one").unwrap();
        let c = cap(d.path()).unwrap();
        assert!(c.bytes(Path::new("../a")).is_err());
    }
    #[test]
    fn explicit_service_root_singleton_reopens_without_sibling_capture() {
        let d = fixture();
        let root = d.path().join("config");
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o750)).unwrap();
        let file = root.join("aegis.toml");
        fs::write(&file, b"synthetic service config").unwrap();
        fs::set_permissions(&file, fs::Permissions::from_mode(0o640)).unwrap();
        fs::write(root.join("unselected"), b"sibling").unwrap();
        let captured = CapturedTree::capture_service_file(
            &file,
            &root,
            root.clone(),
            role(),
            CaptureLimits::default(),
        )
        .unwrap();
        assert_eq!(captured.entries().count(), 1);
        assert!(captured.bytes(Path::new("aegis.toml")).unwrap() == b"synthetic service config");
        let record = captured.export_private_generation().unwrap();
        assert!(record.service_root() == Some(root.as_path()));
        assert!(reopen_generation(&record).is_err());
        let guard = reopen_service_generation(&record, &root).unwrap();
        fs::write(root.join("another-sibling"), b"not selected").unwrap();
        guard.revalidate().unwrap();
        assert!(reopen_service_generation(&record, d.path()).is_err());
        fs::write(&file, b"changed selected bytes").unwrap();
        assert!(guard.revalidate().is_err());
        assert!(reopen_service_generation(&record, &root).is_err());
    }
    #[test]
    fn service_boundary_rejects_sibling_outside_alias_and_nonservice_roles() {
        let d = fixture();
        let root = d.path().join("config");
        let sibling = d.path().join("config-other");
        fs::create_dir(&root).unwrap();
        fs::create_dir(&sibling).unwrap();
        let file = root.join("config");
        let outside = sibling.join("config");
        fs::write(&file, b"inside").unwrap();
        fs::write(&outside, b"outside").unwrap();
        for target in [&outside, &root, &root.join("../config-other/config")] {
            assert!(CapturedTree::capture_service_file(
                target,
                &root,
                root.clone(),
                role(),
                CaptureLimits::default()
            )
            .is_err());
        }
        let uid = unsafe { libc::geteuid() };
        for forbidden in [
            InputRole::AdministratorMetadata {
                administrator_uid: uid,
            },
            InputRole::PrivateCredential { expected_uid: uid },
            InputRole::ExplicitBundleData {
                operator_uid: uid,
                administrator_uid: uid,
            },
        ] {
            assert!(CapturedTree::capture_service_file(
                &file,
                &root,
                root.clone(),
                forbidden,
                CaptureLimits::default()
            )
            .is_err());
        }
        assert!(CapturedTree::capture_service_file(
            &file,
            Path::new("/"),
            root.clone(),
            role(),
            CaptureLimits::default()
        )
        .is_err());
        let alias = d.path().join("alias");
        symlink(&root, &alias).unwrap();
        assert!(CapturedTree::capture_service_file(
            &alias.join("config"),
            &alias,
            root.clone(),
            role(),
            CaptureLimits::default()
        )
        .is_err());
        fs::set_permissions(&root, fs::Permissions::from_mode(0o770)).unwrap();
        assert!(CapturedTree::capture_service_file(
            &file,
            &root,
            root.clone(),
            role(),
            CaptureLimits::default()
        )
        .is_err());
    }
    #[test]
    fn optional_service_boundary_absence_reopen_and_creation_refuse() {
        let d = fixture();
        let root = d.path().join("new-config");
        let file = root.join("tls/ca.pem");
        let captured = CapturedTree::capture_optional_service_file(
            &file,
            &root,
            root.clone(),
            role(),
            CaptureLimits::default(),
        )
        .unwrap();
        assert!(matches!(&captured, CapturedInput::Absent(_)));
        let record = captured.export_private_generation().unwrap();
        assert!(reopen_generation(&record).is_err());
        let guard = reopen_service_generation(&record, &root).unwrap();
        guard.revalidate().unwrap();
        fs::create_dir(&root).unwrap();
        assert!(guard.revalidate().is_err());
        assert!(reopen_service_generation(&record, &root).is_err());
        let captured = CapturedTree::capture_optional_service_file(
            &file,
            &root,
            root.clone(),
            role(),
            CaptureLimits::default(),
        )
        .unwrap();
        let record = captured.export_private_generation().unwrap();
        let guard = reopen_service_generation(&record, &root).unwrap();
        fs::create_dir(root.join("tls")).unwrap();
        assert!(guard.revalidate().is_err());
    }
    #[test]
    fn service_parent_root_replacement_and_private_policy_remain_refused() {
        let d = fixture();
        let root = d.path().join("config");
        fs::create_dir(&root).unwrap();
        let file = root.join("ca.pem");
        fs::write(&file, b"certificate fixture").unwrap();
        let captured = CapturedTree::capture_service_file(
            &file,
            &root,
            root.clone(),
            role(),
            CaptureLimits::default(),
        )
        .unwrap();
        let record = captured.export_private_generation().unwrap();
        let guard = reopen_service_generation(&record, &root).unwrap();
        fs::rename(&root, d.path().join("old-root")).unwrap();
        fs::create_dir(&root).unwrap();
        fs::write(&file, b"certificate fixture").unwrap();
        assert!(guard.revalidate().is_err());
        assert!(reopen_service_generation(&record, &root).is_err());
        let uid = unsafe { libc::geteuid() };
        fs::set_permissions(&file, fs::Permissions::from_mode(0o640)).unwrap();
        assert!(CapturedTree::capture_file(
            &file,
            root.clone(),
            InputRole::PrivateCredential { expected_uid: uid },
            CaptureLimits::default()
        )
        .is_err());
        let ordinary =
            CapturedTree::capture_file(&file, root.clone(), role(), CaptureLimits::default())
                .unwrap();
        let old = ordinary.export_private_generation().unwrap();
        assert!(old.service_root().is_none());
        assert!(!serde_json::to_value(&old)
            .unwrap()
            .as_object()
            .unwrap()
            .contains_key("service_root"));
        reopen_generation(&old).unwrap().revalidate().unwrap();
    }
    #[test]
    #[ignore = "Requires explicitly authorized disposable root Linux ownership fixture"]
    fn installed_service_uid0750_admitted_only_at_exact_boundary_and_no_admin_ancestor_gain() {
        assert_eq!(
            unsafe { libc::geteuid() },
            0,
            "explicit disposable root fixture required"
        );
        let d = fixture();
        let root = d.path().join("config");
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o750)).unwrap();
        let file = root.join("config");
        fs::write(&file, b"synthetic installed config").unwrap();
        fs::set_permissions(&file, fs::Permissions::from_mode(0o640)).unwrap();
        use std::os::unix::ffi::OsStrExt;
        for path in [&root, &file] {
            let name = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
            assert_eq!(unsafe { libc::chown(name.as_ptr(), 65534, 65534) }, 0);
        }
        let service = InputRole::ServiceInput {
            service_uid: 65534,
            administrator_uid: 0,
        };
        assert!(
            CapturedTree::capture_file(&file, root.clone(), service, CaptureLimits::default())
                .is_err()
        );
        let c = CapturedTree::capture_service_file(
            &file,
            &root,
            root.clone(),
            service,
            CaptureLimits::default(),
        )
        .unwrap();
        let r = c.export_private_generation().unwrap();
        reopen_service_generation(&r, &root)
            .unwrap()
            .revalidate()
            .unwrap();
        let nested = root.join("nested-root");
        fs::create_dir(&nested).unwrap();
        let leaf = nested.join("config");
        fs::write(&leaf, b"synthetic").unwrap();
        assert!(CapturedTree::capture_service_file(
            &leaf,
            &nested,
            nested.clone(),
            service,
            CaptureLimits::default()
        )
        .is_err());
        assert!(CapturedTree::capture_file(
            &file,
            root.clone(),
            InputRole::AdministratorMetadata {
                administrator_uid: 0
            },
            CaptureLimits::default()
        )
        .is_err());
        assert!(CapturedTree::capture_file(
            &file,
            root.clone(),
            InputRole::PrivateCredential { expected_uid: 0 },
            CaptureLimits::default()
        )
        .is_err());
    }
}
