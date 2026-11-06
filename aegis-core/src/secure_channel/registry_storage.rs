//! Durable registry publication. The independent floor is committed before the
//! snapshot, so interruption can deny authorization but cannot revive an older
//! generation. Both files remain under the operator's filesystem trust boundary.

use super::{invalid, registry_digest, DeviceRegistry, MAX_REGISTRY_BYTES};
use serde::{Deserialize, Serialize};
#[cfg(feature = "device-enrollment")]
use sha2::Digest;
use std::fs::{self, File, Metadata, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

const MAX_FLOOR_BYTES: u64 = 4096;

/// Authority-private, permanent exact-ID enrollment cancellation. It is not a
/// delivered policy, a replacement floor, or proof of live relay adoption.
#[cfg(feature = "device-enrollment")]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnrollmentCancellation {
    version: u8,
    pub device_id: String,
    pub expected_certificate_sha256: Option<String>,
    pub cancelled_certificate_sha256: Option<String>,
    pub predecessor_generation: u64,
    pub predecessor_sha256: String,
}

#[cfg(feature = "device-enrollment")]
impl EnrollmentCancellation {
    /// Derive only this ID's revoked/consumed successor. This is data, not an
    /// authorization to reset a floor or accept a different pending snapshot.
    pub fn cancelled_snapshot(
        &self,
        current: &DeviceRegistry,
    ) -> io::Result<Option<DeviceRegistry>> {
        if current.generation < self.predecessor_generation
            || (current.generation == self.predecessor_generation
                && hex::encode(registry_digest(current)?) != self.predecessor_sha256)
        {
            return Err(invalid("cancellation predecessor changed"));
        }
        let mut next = current.clone();
        let mut changed = current.generation == self.predecessor_generation;
        if let Some(row) = next
            .devices
            .iter_mut()
            .find(|row| row.device_id == self.device_id)
        {
            if Some(row.certificate_sha256.as_str()) != self.cancelled_certificate_sha256.as_deref()
            {
                return Err(invalid("cancelled certificate target changed"));
            }
            changed |= !row.revoked;
            row.revoked = true;
        } else if self.cancelled_certificate_sha256.is_some() {
            return Err(invalid("cancelled certificate target missing"));
        }
        for invitation in next
            .invitations
            .iter_mut()
            .filter(|row| row.device_id == self.device_id)
        {
            changed |= !invitation.consumed;
            invitation.consumed = true;
        }
        if !changed {
            return Ok(None);
        }
        next.generation = next
            .generation
            .checked_add(1)
            .ok_or_else(|| invalid("device generation exhausted"))?;
        next.validate()?;
        Ok(Some(next))
    }
}

fn cancellation_path(path: &Path, device_id: &str) -> io::Result<PathBuf> {
    super::validate_device_id(device_id)?;
    let mut name = path.as_os_str().to_os_string();
    name.push(format!(".enrollment-cancel-{device_id}.json"));
    Ok(name.into())
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RegistryFloor {
    version: u8,
    generation: u64,
    snapshot_sha256: String,
}

impl RegistryFloor {
    fn for_snapshot(registry: &DeviceRegistry) -> io::Result<Self> {
        registry.validate()?;
        Ok(Self {
            version: 1,
            generation: registry.generation,
            snapshot_sha256: hex::encode(registry_digest(registry)?),
        })
    }

    fn matches(&self, registry: &DeviceRegistry) -> io::Result<bool> {
        Ok(*self == Self::for_snapshot(registry)?)
    }
}

pub fn floor_path(path: &Path) -> PathBuf {
    let mut sidecar = path.as_os_str().to_os_string();
    sidecar.push(".floor");
    PathBuf::from(sidecar)
}

pub fn pending_path(path: &Path) -> PathBuf {
    let mut sidecar = path.as_os_str().to_os_string();
    sidecar.push(".pending");
    PathBuf::from(sidecar)
}

/// Authority-private issuance journal; never a member of exported snapshots.
pub fn issuance_pending_path(path: &Path) -> PathBuf {
    let mut sidecar = path.as_os_str().to_os_string();
    sidecar.push(".issuance.pending");
    PathBuf::from(sidecar)
}

fn reject_issuance_barrier(path: &Path) -> io::Result<()> {
    match fs::symlink_metadata(issuance_pending_path(path)) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
        Ok(_) => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "authority issuance journal requires exact recovery",
        )),
    }
}

fn reject_cancelled_active(path: &Path, registry: &DeviceRegistry) -> io::Result<()> {
    for device in registry.devices.iter().filter(|device| !device.revoked) {
        match fs::symlink_metadata(cancellation_path(path, &device.device_id)?) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
            Ok(_) => return Err(invalid("active device has a durable cancellation intent")),
        }
    }
    Ok(())
}

fn open_file(path: &Path, limit: u64) -> io::Result<(File, Metadata)> {
    let parent = crate::secret_file::trusted_read_parent(path)?;
    let path = parent.join(
        path.file_name()
            .ok_or_else(|| invalid("registry needs a filename"))?,
    );
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = options.open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() > limit {
        return Err(invalid("registry input must be a bounded regular file"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        // SAFETY: these calls only read this process's effective identity.
        let uid = unsafe { libc::geteuid() };
        let gid = unsafe { libc::getegid() };
        let service_group = metadata.uid() == 0 && (uid == 0 || metadata.gid() == gid);
        let forbidden = if service_group { 0o037 } else { 0o077 };
        if (metadata.uid() != 0 && metadata.uid() != uid)
            || metadata.mode() & forbidden != 0
            || metadata.nlink() != 1
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "registry input requires an unlinked owner-private or root:service 0640 file",
            ));
        }
    }
    Ok((file, metadata))
}

fn read_file(path: &Path, limit: u64) -> io::Result<(Vec<u8>, Metadata)> {
    let (file, metadata) = open_file(path, limit)?;
    let mut bytes = Vec::new();
    file.take(limit + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit {
        return Err(invalid("registry input exceeds bound"));
    }
    Ok((bytes, metadata))
}

fn parse_snapshot(bytes: &[u8]) -> io::Result<DeviceRegistry> {
    let registry: DeviceRegistry =
        serde_json::from_slice(bytes).map_err(|_| invalid("device registry JSON invalid"))?;
    registry.validate()?;
    Ok(registry)
}

pub(super) fn load_snapshot(path: &Path) -> io::Result<DeviceRegistry> {
    parse_snapshot(&read_file(path, MAX_REGISTRY_BYTES)?.0)
}

fn load_floor(path: &Path) -> io::Result<RegistryFloor> {
    let floor: RegistryFloor = serde_json::from_slice(&read_file(path, MAX_FLOOR_BYTES)?.0)
        .map_err(|_| invalid("device registry floor JSON invalid"))?;
    if floor.version != 1 || floor.generation == 0 || super::digest(&floor.snapshot_sha256).is_err()
    {
        return Err(invalid("device registry floor invalid"));
    }
    Ok(floor)
}

pub(super) fn load_verified(path: &Path) -> io::Result<DeviceRegistry> {
    let mut sidecar = path.as_os_str().to_os_string();
    sidecar.push(".lock");
    let (lock, _) = open_file(Path::new(&sidecar), 0)?;
    match lock.try_lock_shared() {
        Ok(()) => load_verified_locked(path),
        Err(fs::TryLockError::WouldBlock) => Err(io::Error::new(
            io::ErrorKind::WouldBlock,
            "device registry publication is in progress",
        )),
        Err(fs::TryLockError::Error(error)) => Err(error),
    }
}

fn load_verified_locked(path: &Path) -> io::Result<DeviceRegistry> {
    reject_issuance_barrier(path)?;
    let registry = load_verified_pair(path)?;
    reject_cancelled_active(path, &registry)?;
    Ok(registry)
}

fn load_verified_pair(path: &Path) -> io::Result<DeviceRegistry> {
    let floor_path = floor_path(path);
    let before = load_floor(&floor_path)?;
    let registry = load_snapshot(path)?;
    let after = load_floor(&floor_path)?;
    if before != after || !after.matches(&registry)? {
        return Err(invalid(
            "device registry snapshot does not match durable floor",
        ));
    }
    Ok(registry)
}

fn optional<T>(value: io::Result<T>) -> io::Result<Option<T>> {
    match value {
        Ok(value) => Ok(Some(value)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

/// Authenticated issuer journal descriptor. The issuer validates its retained
/// receipt/certificate before supplying this exact predecessor/successor.
#[cfg(feature = "device-enrollment")]
pub struct CancellationJournal<'a> {
    pub predecessor_generation: u64,
    pub predecessor_sha256: &'a str,
    pub successor: &'a DeviceRegistry,
}

/// Validated facts only; no raw snapshot bypass or filesystem mutation API.
#[cfg(feature = "device-enrollment")]
pub struct CancellationObservation {
    pub snapshot: DeviceRegistry,
    pub intent: Option<EnrollmentCancellation>,
    pub intent_sha256: Option<String>,
    pub snapshot_file_sha256: String,
    pub floor_generation: u64,
    pub floor_snapshot_sha256: String,
    pub floor_file_sha256: String,
    pub pending_file_sha256: Option<String>,
}

/// An existing trusted read-only lock. This type deliberately has no save,
/// apply, recovery, transaction conversion, or mutable registry methods.
#[cfg(feature = "device-enrollment")]
pub struct CancellationReadGuard {
    _lock: File,
    path: PathBuf,
}

#[cfg(feature = "device-enrollment")]
impl CancellationReadGuard {
    pub fn open(path: &Path) -> io::Result<Self> {
        if !cfg!(unix) || !path.is_absolute() {
            return Err(invalid(
                "cancellation inspection requires an absolute Unix registry",
            ));
        }
        let parent = crate::secret_file::trusted_read_parent(path)?;
        let path = parent.join(
            path.file_name()
                .ok_or_else(|| invalid("registry needs a filename"))?,
        );
        let mut name = path.as_os_str().to_os_string();
        name.push(".lock");
        let (lock, _) = open_file(Path::new(&name), 0)?;
        match lock.try_lock_shared() {
            Ok(()) => Ok(Self { _lock: lock, path }),
            Err(fs::TryLockError::WouldBlock) => Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "cancellation inspection busy",
            )),
            Err(fs::TryLockError::Error(error)) => Err(error),
        }
    }

    pub fn observe(
        &self,
        device_id: &str,
        journal: Option<&CancellationJournal<'_>>,
    ) -> io::Result<CancellationObservation> {
        observe_cancellation(&self.path, device_id, journal)
    }
}

#[cfg(feature = "device-enrollment")]
fn load_cancellation_snapshot_at(
    path: &Path,
    predecessor_generation: u64,
    predecessor_sha256: &str,
    successor: &DeviceRegistry,
) -> io::Result<DeviceRegistry> {
    super::digest(predecessor_sha256)?;
    let floor = load_floor(&floor_path(path))?;
    let current = load_snapshot(path)?;
    let next = RegistryFloor::for_snapshot(successor)?;
    let predecessor = RegistryFloor {
        version: 1,
        generation: predecessor_generation,
        snapshot_sha256: predecessor_sha256.to_owned(),
    };
    let actual = RegistryFloor::for_snapshot(&current)?;
    let pending = optional(load_snapshot(&pending_path(path)))?;
    if pending
        .as_ref()
        .map(|value| next.matches(value))
        .transpose()?
        .is_some_and(|matches| !matches)
        || (actual != predecessor && actual != next)
        || (floor != actual && !(actual == predecessor && floor == next && pending.is_some()))
    {
        return Err(invalid(
            "cancellation journal does not match published floor/snapshot",
        ));
    }
    Ok(current)
}

#[cfg(feature = "device-enrollment")]
fn load_cancellation_intent(
    registry_path: &Path,
    device_id: &str,
) -> io::Result<Option<(EnrollmentCancellation, String)>> {
    let path = cancellation_path(registry_path, device_id)?;
    let Some((bytes, metadata)) = optional(read_file(&path, 1024))? else {
        return Ok(None);
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        // SAFETY: geteuid only observes the transaction's caller identity.
        if metadata.uid() != unsafe { libc::geteuid() } || metadata.mode() & 0o7777 != 0o600 {
            return Err(invalid(
                "cancellation intent requires exact owner-private custody",
            ));
        }
    }
    #[cfg(not(unix))]
    let _ = metadata;
    let value: EnrollmentCancellation =
        serde_json::from_slice(&bytes).map_err(|_| invalid("cancellation intent invalid"))?;
    if value.version != 1 || value.device_id != device_id {
        return Err(invalid("cancellation intent identity changed"));
    }
    if let Some(expected) = &value.expected_certificate_sha256 {
        super::digest(expected)?;
    }
    if let Some(cancelled) = &value.cancelled_certificate_sha256 {
        super::digest(cancelled)?;
    }
    if value.expected_certificate_sha256.is_some() && value.cancelled_certificate_sha256.is_none() {
        return Err(invalid("published cancellation target missing"));
    }
    if value.predecessor_generation == 0 {
        return Err(invalid("cancellation predecessor generation invalid"));
    }
    super::digest(&value.predecessor_sha256)?;
    Ok(Some((value, hex::encode(super::Sha256::digest(&bytes)))))
}

// Read-only equivalent of the standalone cancellation checks before apply.
#[cfg(feature = "device-enrollment")]
fn validate_standalone_cancellation(
    path: &Path,
    intent: &EnrollmentCancellation,
) -> io::Result<(DeviceRegistry, DeviceRegistry)> {
    let floor = load_floor(&floor_path(path))?;
    let current = load_snapshot(path)?;
    if current.devices.iter().any(|row| {
        row.device_id == intent.device_id
            && !row.revoked
            && Some(row.certificate_sha256.as_str())
                != intent.expected_certificate_sha256.as_deref()
    }) {
        return Err(invalid(
            "published cancellation replay requires exact certificate expectation",
        ));
    }
    let cancelled = intent
        .cancelled_snapshot(&current)?
        .unwrap_or(current.clone());
    let expected = RegistryFloor::for_snapshot(&cancelled)?;
    match optional(load_snapshot(&pending_path(path)))? {
        Some(pending) => {
            if !expected.matches(&pending)? || (!floor.matches(&current)? && floor != expected) {
                return Err(invalid("pending snapshot is not this exact cancellation"));
            }
        }
        None => {
            if !floor.matches(&current)? {
                return Err(invalid("cancellation requires its existing durable pair"));
            }
        }
    }
    Ok((current, cancelled))
}

#[cfg(feature = "device-enrollment")]
fn observe_cancellation(
    path: &Path,
    device_id: &str,
    journal: Option<&CancellationJournal<'_>>,
) -> io::Result<CancellationObservation> {
    super::validate_device_id(device_id)?;
    let has_journal = fs::symlink_metadata(issuance_pending_path(path));
    match (journal.is_some(), has_journal) {
        (false, Err(error)) if error.kind() == io::ErrorKind::NotFound => {}
        (true, Ok(_)) => {}
        (_, Err(error)) => return Err(error),
        _ => return Err(invalid("cancellation journal descriptor mismatch")),
    }
    let retained = load_cancellation_intent(path, device_id)?;
    let snapshot = match (journal, retained.as_ref()) {
        (Some(journal), None) => load_cancellation_snapshot_at(
            path,
            journal.predecessor_generation,
            journal.predecessor_sha256,
            journal.successor,
        )?,
        (Some(journal), Some((intent, _))) => {
            let next = RegistryFloor::for_snapshot(journal.successor)?;
            let predecessor = RegistryFloor {
                version: 1,
                generation: journal.predecessor_generation,
                snapshot_sha256: journal.predecessor_sha256.to_owned(),
            };
            super::digest(&predecessor.snapshot_sha256)?;
            if !((intent.predecessor_generation == predecessor.generation
                && intent.predecessor_sha256 == predecessor.snapshot_sha256)
                || (intent.predecessor_generation == next.generation
                    && intent.predecessor_sha256 == next.snapshot_sha256))
            {
                return Err(invalid(
                    "cancellation intent conflicts with journal predecessor",
                ));
            }
            let cancelled = intent
                .cancelled_snapshot(journal.successor)?
                .ok_or_else(|| invalid("journal cancellation successor missing"))?;
            let cancelled_floor = RegistryFloor::for_snapshot(&cancelled)?;
            let floor = load_floor(&floor_path(path))?;
            let current = load_snapshot(path)?;
            let actual = RegistryFloor::for_snapshot(&current)?;
            let pending = optional(load_snapshot(&pending_path(path)))?;
            // Exact P/S/C only. Pending C may precede its floor publication;
            // recover C directly in that cut rather than trying to reapply S.
            let incoming = if floor == cancelled_floor
                || pending
                    .as_ref()
                    .map(|p| cancelled_floor.matches(p))
                    .transpose()?
                    .unwrap_or(false)
            {
                &cancelled_floor
            } else {
                &next
            };
            if ![&predecessor, &next, &cancelled_floor].contains(&&floor)
                || ![&predecessor, &next, &cancelled_floor].contains(&&actual)
                || actual.generation > floor.generation
                || pending
                    .as_ref()
                    .map(|p| incoming.matches(p))
                    .transpose()?
                    .is_some_and(|v| !v)
                || (actual != floor && !(incoming == &floor && pending.is_some()))
            {
                return Err(invalid("cancelled journal floor/snapshot/pending conflict"));
            }
            current
        }
        (None, Some((intent, _))) => {
            reject_issuance_barrier(path)?;
            validate_standalone_cancellation(path, intent)?.0
        }
        (None, None) => {
            if optional(load_snapshot(&pending_path(path)))?.is_some() {
                return Err(invalid("unrelated pending snapshot blocks inspection"));
            }
            load_verified_locked(path)?
        }
    };
    let floor = load_floor(&floor_path(path))?;
    let snapshot_bytes = read_file(path, MAX_REGISTRY_BYTES)?.0;
    if registry_digest(&parse_snapshot(&snapshot_bytes)?)? != registry_digest(&snapshot)? {
        return Err(invalid("cancellation snapshot changed during observation"));
    }
    let pending_bytes = optional(read_file(&pending_path(path), MAX_REGISTRY_BYTES))?;
    Ok(CancellationObservation {
        snapshot,
        intent: retained.as_ref().map(|(intent, _)| intent.clone()),
        intent_sha256: retained.map(|(_, digest)| digest),
        snapshot_file_sha256: hex::encode(super::Sha256::digest(&snapshot_bytes)),
        floor_generation: floor.generation,
        floor_snapshot_sha256: floor.snapshot_sha256,
        floor_file_sha256: hex::encode(super::Sha256::digest(
            read_file(&floor_path(path), MAX_FLOOR_BYTES)?.0,
        )),
        pending_file_sha256: pending_bytes
            .map(|(bytes, _)| hex::encode(super::Sha256::digest(bytes))),
    })
}

/// One interprocess lock covers the complete operator read/modify/publication.
pub struct RegistryTransaction {
    _lock: File,
    path: PathBuf,
    parent: PathBuf,
    issuance: bool,
}

impl RegistryTransaction {
    pub fn begin(path: &Path) -> io::Result<Self> {
        Self::begin_inner(path, false)
    }

    /// The issuer engine owns journal authentication and holds this same lock
    /// across journal, snapshot and receipt publication. This grants no floor
    /// reset or arbitrary pending replacement capability.
    #[cfg(feature = "device-enrollment")]
    pub fn begin_issuance(path: &Path) -> io::Result<Self> {
        Self::begin_inner(path, true)
    }

    fn begin_inner(path: &Path, issuance: bool) -> io::Result<Self> {
        // Client enrollment has a Windows ACL writer; the server's paired
        // registry/floor transaction still requires its Unix durability path.
        if !cfg!(unix) {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "server registry publication requires Unix durability support",
            ));
        }

        let parent = crate::secret_file::trusted_parent(path)?;
        let path = parent.join(
            path.file_name()
                .ok_or_else(|| invalid("registry needs a filename"))?,
        );
        let mut sidecar = path.as_os_str().to_os_string();
        sidecar.push(".lock");
        let mut options = OpenOptions::new();
        options.create(true).truncate(false).read(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
        }
        let file = options.open(PathBuf::from(sidecar))?;
        let metadata = file.metadata()?;
        if !metadata.is_file() || metadata.len() != 0 {
            return Err(invalid(
                "device registry lock must be an empty regular file",
            ));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            // SAFETY: geteuid only reads this process's effective identity.
            let uid = unsafe { libc::geteuid() };
            let forbidden = if uid == 0 { 0o037 } else { 0o077 };
            if metadata.uid() != uid || metadata.mode() & forbidden != 0 || metadata.nlink() != 1 {
                return Err(invalid("device registry lock ownership invalid"));
            }
        }
        let started = Instant::now();
        loop {
            match file.try_lock() {
                Ok(()) => break,
                Err(fs::TryLockError::WouldBlock) if started.elapsed() < Duration::from_secs(5) => {
                    std::thread::sleep(Duration::from_millis(20));
                }
                Err(fs::TryLockError::WouldBlock) => {
                    return Err(io::Error::new(
                        io::ErrorKind::WouldBlock,
                        "device registry transaction busy",
                    ));
                }
                Err(fs::TryLockError::Error(error)) => return Err(error),
            }
        }
        // Reuse the lock inode across publications. A root:service registry
        // permits the same service to obtain a read-only shared lock.
        if let Some((_, metadata)) = optional(read_file(&path, MAX_REGISTRY_BYTES))? {
            preserve_permissions(&file, &metadata)?;
            file.sync_all()?;
        }
        if !issuance {
            reject_issuance_barrier(&path)?;
        }
        Ok(Self {
            _lock: file,
            path,
            parent,
            issuance,
        })
    }

    /// Verified operator read while this transaction already owns the lock.
    pub fn load(&self) -> io::Result<DeviceRegistry> {
        if optional(load_snapshot(&pending_path(&self.path)))?.is_some() {
            return Err(invalid(
                "pending registry snapshot requires explicit apply-snapshot recovery",
            ));
        }
        if self.issuance {
            let registry = load_verified_pair(&self.path)?;
            reject_cancelled_active(&self.path, &registry)?;
            Ok(registry)
        } else {
            load_verified_locked(&self.path)
        }
    }

    #[cfg(feature = "device-enrollment")]
    pub fn observe_enrollment_cancellation(
        &self,
        device_id: &str,
        journal: Option<&CancellationJournal<'_>>,
    ) -> io::Result<CancellationObservation> {
        if !self.issuance {
            return Err(invalid("issuance transaction required"));
        }
        observe_cancellation(&self.path, device_id, journal)
    }

    #[cfg(feature = "device-enrollment")]
    pub fn issuance_pending_matches(&self, snapshot: &DeviceRegistry) -> io::Result<bool> {
        if !self.issuance {
            return Err(invalid("issuance transaction required"));
        }
        let expected = RegistryFloor::for_snapshot(snapshot)?;
        Ok(optional(load_snapshot(&pending_path(&self.path)))?
            .as_ref()
            .map(|pending| expected.matches(pending))
            .transpose()?
            .unwrap_or(false))
    }

    /// Observe the durable pair while recovering this authority's journal.
    /// The existing generation/digest floor remains mandatory.
    #[cfg(feature = "device-enrollment")]
    pub fn load_published_issuance(&self) -> io::Result<DeviceRegistry> {
        if !self.issuance {
            return Err(invalid("issuance transaction required"));
        }
        load_verified_pair(&self.path)
    }

    /// The issuer has authenticated this journal. Accept only its exact
    /// predecessor/successor and an existing valid floor, including the crash
    /// cut where that floor advanced before the snapshot. No floor is recreated.
    #[cfg(feature = "device-enrollment")]
    pub fn load_cancellation_snapshot(
        &self,
        predecessor_generation: u64,
        predecessor_sha256: &str,
        successor: &DeviceRegistry,
    ) -> io::Result<DeviceRegistry> {
        if !self.issuance {
            return Err(invalid("issuance transaction required"));
        }
        load_cancellation_snapshot_at(
            &self.path,
            predecessor_generation,
            predecessor_sha256,
            successor,
        )
    }

    #[cfg(feature = "device-enrollment")]
    pub fn issuance_floor_matches(&self, snapshot: &DeviceRegistry) -> io::Result<bool> {
        if !self.issuance {
            return Err(invalid("issuance transaction required"));
        }
        load_floor(&floor_path(&self.path))?.matches(snapshot)
    }

    /// Only called while this transaction owns the registry lock. Missing is
    /// ordinary uncancelled state; corrupt, foreign or unsafe intent refuses.
    #[cfg(feature = "device-enrollment")]
    pub fn enrollment_cancellation(
        &self,
        device_id: &str,
    ) -> io::Result<Option<EnrollmentCancellation>> {
        Ok(load_cancellation_intent(&self.path, device_id)?.map(|(value, _)| value))
    }

    /// Durable intent precedes journal completion. It is never overwritten or
    /// removed, and exact replay cannot change its certificate expectation.
    #[cfg(feature = "device-enrollment")]
    pub fn record_enrollment_cancellation(
        &self,
        device_id: &str,
        expected_certificate_sha256: Option<&str>,
        cancelled_certificate_sha256: Option<&str>,
        predecessor: &DeviceRegistry,
    ) -> io::Result<()> {
        if !self.issuance {
            return Err(invalid("issuance transaction required"));
        }
        if let Some(expected) = expected_certificate_sha256 {
            super::digest(expected)?;
        }
        if let Some(cancelled) = cancelled_certificate_sha256 {
            super::digest(cancelled)?;
        }
        let value = EnrollmentCancellation {
            version: 1,
            device_id: device_id.to_owned(),
            expected_certificate_sha256: expected_certificate_sha256.map(str::to_owned),
            cancelled_certificate_sha256: cancelled_certificate_sha256.map(str::to_owned),
            predecessor_generation: predecessor.generation,
            predecessor_sha256: hex::encode(registry_digest(predecessor)?),
        };
        let path = cancellation_path(&self.path, device_id)?;
        if let Some(existing) = self.enrollment_cancellation(device_id)? {
            if existing != value {
                return Err(invalid("cancellation intent replay changed"));
            }
            open_file(&path, 1024)?.0.sync_all()?;
            return File::open(&self.parent)?.sync_all();
        }
        self.atomic_write(
            &path,
            &serde_json::to_vec(&value).map_err(io::Error::other)?,
            None,
            true,
        )
    }

    /// Complete only the exact retained cancellation's paired publication.
    /// The issuer journal must already be settled, and an existing floor is
    /// mandatory. An interrupted unrelated snapshot is never overwritten.
    #[cfg(feature = "device-enrollment")]
    pub fn complete_enrollment_cancellation(&self, device_id: &str) -> io::Result<()> {
        if !self.issuance {
            return Err(invalid("issuance transaction required"));
        }
        reject_issuance_barrier(&self.path)?;
        let intent = self
            .enrollment_cancellation(device_id)?
            .ok_or_else(|| invalid("durable cancellation intent missing"))?;
        let (_, cancelled) = validate_standalone_cancellation(&self.path, &intent)?;
        self.apply(&cancelled)
    }

    /// Publish the exact successor already retained in the private journal.
    /// Existing pending/floor checks reject a different interrupted snapshot.
    #[cfg(feature = "device-enrollment")]
    pub fn apply_issuance_snapshot(&self, registry: &DeviceRegistry) -> io::Result<()> {
        if !self.issuance || fs::symlink_metadata(issuance_pending_path(&self.path)).is_err() {
            return Err(invalid(
                "durable issuance journal required before publication",
            ));
        }
        self.apply(registry)
    }

    pub fn save(&self, path: &Path, registry: &DeviceRegistry, new: bool) -> io::Result<()> {
        let parent = crate::secret_file::trusted_parent(path)?;
        if parent.join(
            path.file_name()
                .ok_or_else(|| invalid("registry needs a filename"))?,
        ) != self.path
        {
            return Err(invalid("registry transaction destination changed"));
        }
        if new {
            if optional(read_file(&self.path, MAX_REGISTRY_BYTES))?.is_some()
                || optional(load_floor(&floor_path(&self.path)))?.is_some()
                || optional(load_snapshot(&pending_path(&self.path)))?.is_some()
            {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "registry or floor already exists",
                ));
            }
        } else {
            // Ordinary enrollment cannot silently repair an interrupted pair.
            self.load()?;
        }
        self.apply(registry)
    }

    fn apply(&self, registry: &DeviceRegistry) -> io::Result<()> {
        if !self.issuance {
            reject_issuance_barrier(&self.path)?;
        }
        let incoming = RegistryFloor::for_snapshot(registry)?;
        let bytes = serde_json::to_vec_pretty(registry).map_err(io::Error::other)?;
        if bytes.len() as u64 > MAX_REGISTRY_BYTES {
            return Err(invalid("device registry exceeds bound"));
        }
        let floor_name = floor_path(&self.path);
        let floor = optional(load_floor(&floor_name))?;
        let existing = optional(read_file(&self.path, MAX_REGISTRY_BYTES))?;
        let pending_name = pending_path(&self.path);
        let pending = optional(load_snapshot(&pending_name))?;
        if let Some(pending) = &pending {
            if !incoming.matches(pending)? {
                return Err(invalid(
                    "existing pending registry snapshot must not be overwritten",
                ));
            }
        }
        match (&floor, &existing) {
            (None, Some(_)) => return Err(invalid("existing registry has no durable floor")),
            (Some(floor), existing) => {
                if incoming.generation < floor.generation
                    || (incoming.generation == floor.generation && incoming != *floor)
                {
                    return Err(invalid(
                        "registry rollback or same-generation equivocation rejected",
                    ));
                }
                let current = existing
                    .as_ref()
                    .and_then(|(bytes, _)| parse_snapshot(bytes).ok());
                if current
                    .as_ref()
                    .is_some_and(|current| current.generation > floor.generation)
                {
                    return Err(invalid("durable floor is older than the registry"));
                }
                let healthy = current
                    .as_ref()
                    .map(|current| floor.matches(current))
                    .transpose()?
                    .unwrap_or(false);
                if !healthy && incoming != *floor {
                    return Err(invalid(
                        "interrupted registry publication requires the exact floor snapshot",
                    ));
                }
                if healthy && incoming == *floor {
                    // A crash after snapshot publication may only have left
                    // cleanup undone. Exact replay confirms durability first.
                    return if pending.is_some() {
                        self.finish_pending(&incoming)
                    } else {
                        Ok(())
                    };
                }
            }
            (None, None) => {}
        }
        let metadata = existing.as_ref().map(|(_, metadata)| metadata);
        let fallback_metadata = if metadata.is_none() && floor.is_some() {
            Some(read_file(&floor_name, MAX_FLOOR_BYTES)?.1)
        } else {
            None
        };
        let metadata = metadata.or(fallback_metadata.as_ref());
        if pending.is_none() {
            // Retain the only exact recovery snapshot before advancing the
            // floor, including for locally produced invite/issue/revoke.
            // It contains registry records only and stays operator-private.
            self.atomic_write(&pending_name, &bytes, None, true)?;
        }
        // The floor inherits the snapshot's reader ownership so root:service
        // 0640 remains readable after every replacement and after recovery.
        self.atomic_write(
            &floor_name,
            &serde_json::to_vec(&incoming).map_err(io::Error::other)?,
            metadata,
            floor.is_none(),
        )?;
        // This call may fail or the process may die here. The durable higher
        // floor makes the old snapshot unusable until exact redelivery.
        self.atomic_write(&self.path, &bytes, metadata, existing.is_none())?;
        self.finish_pending(&incoming)
    }

    fn finish_pending(&self, expected: &RegistryFloor) -> io::Result<()> {
        let published = if self.issuance {
            load_verified_pair(&self.path)?
        } else {
            load_verified_locked(&self.path)?
        };
        if !expected.matches(&published)?
            || !expected.matches(&load_snapshot(&pending_path(&self.path))?)?
        {
            return Err(invalid("registry recovery does not match pending snapshot"));
        }
        for (path, bound) in [
            (&self.path, MAX_REGISTRY_BYTES),
            (&floor_path(&self.path), MAX_FLOOR_BYTES),
        ] {
            open_file(path, bound)?.0.sync_all()?;
        }
        File::open(&self.parent)?.sync_all()?;
        fs::remove_file(pending_path(&self.path))?;
        File::open(&self.parent)?.sync_all()
    }

    fn atomic_write(
        &self,
        path: &Path,
        bytes: &[u8],
        metadata: Option<&Metadata>,
        new: bool,
    ) -> io::Result<()> {
        let mut staging = tempfile::NamedTempFile::new_in(&self.parent)?;
        if let Some(metadata) = metadata {
            preserve_permissions(staging.as_file(), metadata)?;
        }
        staging.write_all(bytes)?;
        staging.as_file().sync_all()?;
        if new {
            staging
                .persist_noclobber(path)
                .map_err(|error| error.error)?;
        } else {
            staging.persist(path).map_err(|error| error.error)?;
        }
        File::open(&self.parent)?.sync_all()
    }
}

fn preserve_permissions(file: &File, metadata: &Metadata) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd;
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let current = file.metadata()?;
        if (current.uid(), current.gid()) != (metadata.uid(), metadata.gid()) {
            // SAFETY: fchown receives a live file descriptor owned by the caller.
            if unsafe { libc::fchown(file.as_raw_fd(), metadata.uid(), metadata.gid()) } != 0 {
                return Err(io::Error::last_os_error());
            }
        }
        if current.mode() & 0o777 != metadata.mode() & 0o640 {
            file.set_permissions(fs::Permissions::from_mode(metadata.mode() & 0o640))?;
        }
    }
    #[cfg(not(unix))]
    let _ = (file, metadata);
    Ok(())
}

/// Deliver an independently trusted operator snapshot; source authentication
/// is external. The source is never accompanied by an authoritative floor.
pub fn apply_snapshot(target: &Path, input: &Path) -> io::Result<()> {
    // Windows must fail before opening or modifying either destination file.
    let transaction = RegistryTransaction::begin(target)?;
    crate::secret_file::trusted_parent(input)?;
    transaction.apply(&load_snapshot(input)?)
}

/// The same durable publication boundary for in-process operator producers.
pub fn publish_snapshot(target: &Path, registry: &DeviceRegistry) -> io::Result<()> {
    RegistryTransaction::begin(target)?.apply(registry)
}

#[cfg(all(test, unix))]
#[path = "registry_storage_tests.rs"]
mod tests;

#[cfg(all(test, not(unix)))]
mod windows_tests {
    #[test]
    fn mutations_fail_before_creating_registry_or_lock() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("registry.json");
        assert_eq!(
            super::publish_snapshot(&path, &super::DeviceRegistry::default())
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::Unsupported
        );
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
    }
}
