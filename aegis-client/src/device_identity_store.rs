//! Device-local enrollment state. The only private key is an immutable file in
//! the final identity directory, outside bundle and config recovery trees.
use super::{CompleteArgs, PrepareArgs};
#[cfg(any(test, target_os = "macos"))]
pub(crate) use aegis_client::online_expectation::OnlineExpectation;
use aegis_client::protected_identity_file::{read_private, validate_file, MAX_INPUT};
#[cfg(unix)]
use aegis_client::protected_identity_store::ProtectedIdentityStore;
use aegis_core::secure_channel::{enrollment, registry};
use anyhow::{bail, ensure, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};

#[path = "device_identity_online.rs"]
mod online;
pub(crate) use online::{
    accept_online_response, begin_online_request, bundle_ready, enable_online, online_expectation,
    online_status, recover_local, resume_online_response, sign_online_request, BundleReadyStatus,
    LocalCompletion, LocalRecovery, OnlineStatus, RequestMaterial,
};
#[cfg(unix)]
pub(crate) use online::{prepare_refresh, replace_refresh_invitation, RefreshSnapshot};

#[cfg(all(test, unix))]
#[path = "device_identity_store_tests.rs"]
mod tests;
#[cfg(all(test, windows))]
#[path = "device_identity_windows_tests.rs"]
mod windows_tests;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    version: u8,
    device_id: String,
    phase: String,
    device_ca_sha256: String,
    certificate_sha256: Option<String>,
}

#[derive(Serialize)]
pub(super) struct Status {
    version: u8,
    device_id: String,
    pub(super) phase: String,
    csr_path: PathBuf,
    key_path: PathBuf,
    certificate_path: PathBuf,
    device_ca_path: PathBuf,
}

struct Store {
    directory: PathBuf,
    #[cfg(windows)]
    _lock: File,
    #[cfg(unix)]
    protected: ProtectedIdentityStore,
    #[cfg(windows)]
    machine: bool,
}

impl Store {
    fn open(directory: &Path, create: bool) -> Result<Self> {
        ensure!(
            directory.is_absolute()
                && !directory
                    .components()
                    .any(|component| matches!(component, Component::ParentDir)),
            "identity directory requires an absolute path without parent traversal"
        );
        // Resolve only after checking the supplied ancestry. Never chmod or
        // adopt an existing directory controlled by a different principal.
        if create {
            create_identity_parents(directory)?;
        }
        enrollment::trusted_parent(directory)?;
        if create && !directory.try_exists()? {
            #[allow(unused_mut)] // Unix sets the creation mode below.
            #[cfg(not(windows))]
            let mut builder = fs::DirBuilder::new();
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                builder.mode(0o700);
            }
            #[cfg(not(windows))]
            let created = builder.create(directory);
            #[cfg(windows)]
            let created =
                aegis_core::windows_file::create_private_directory(directory, false, false);
            match created {
                Ok(()) => aegis_core::secret_file::sync_directory(
                    directory.parent().context("identity parent missing")?,
                )?,
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
        }
        let metadata = fs::symlink_metadata(directory)?;
        ensure!(
            metadata.is_dir(),
            "identity directory must be a real directory"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            // SAFETY: geteuid only reads the process identity.
            ensure!(
                metadata.uid() == unsafe { libc::geteuid() } && metadata.mode() & 0o077 == 0,
                "identity directory requires owner-only access"
            );
        }
        let directory = enrollment::trusted_parent(&directory.join("identity.json"))?;
        #[cfg(windows)]
        let machine = aegis_core::windows_file::trusted_system_directory(&directory).is_ok();
        let mut options = OpenOptions::new();
        options
            .read(true)
            .write(true)
            .create(create)
            .truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
        }
        #[cfg(windows)]
        if create {
            let created = if machine {
                aegis_core::windows_file::create_machine_private_file(&directory.join(".lock"))
            } else {
                aegis_core::windows_file::create_private_file(&directory.join(".lock"), false)
            };
            match created {
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(e.into()),
            }
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            options.create(false).custom_flags(
                windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT,
            );
        }
        let lock = options.open(directory.join(".lock"))?;
        #[cfg(windows)]
        if machine {
            aegis_core::windows_file::validate_machine_private(&lock)?;
        } else {
            aegis_core::windows_file::validate_private(&lock, false)?;
        }
        #[cfg(unix)]
        let protected = ProtectedIdentityStore::adopt(directory.clone(), lock)?;
        #[cfg(windows)]
        {
            validate_file(&lock.metadata()?)?;
            lock.try_lock()
                .context("device enrollment is busy or cannot be locked")?;
        }
        Ok(Self {
            directory,
            #[cfg(windows)]
            _lock: lock,
            #[cfg(unix)]
            protected,
            #[cfg(windows)]
            machine,
        })
    }

    fn path(&self, name: &str) -> PathBuf {
        self.directory.join(name)
    }

    fn read(&self, name: &str) -> Result<zeroize::Zeroizing<Vec<u8>>> {
        #[cfg(unix)]
        return self.protected.read(name);
        // Defined below through the shared strict reader; no private bytes are
        // ever serialized into identity.json, status, logs, or a response.
        #[cfg(windows)]
        if self.machine {
            use std::os::windows::fs::OpenOptionsExt;
            let file = OpenOptions::new()
                .read(true)
                .custom_flags(windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT)
                .open(self.path(name))?;
            aegis_core::windows_file::validate_machine_private(&file)?;
            validate_file(&file.metadata()?)?;
            let mut bytes = zeroize::Zeroizing::new(Vec::new());
            file.take(MAX_INPUT + 1).read_to_end(&mut bytes)?;
            ensure!(
                bytes.len() as u64 <= MAX_INPUT,
                "machine identity input too large"
            );
            return Ok(bytes);
        }
        #[cfg(windows)]
        read_private(&self.path(name))
    }

    fn save(&self, name: &str, bytes: &[u8], replace: bool) -> Result<()> {
        let path = self.path(name);
        #[cfg(windows)]
        {
            if self.machine {
                aegis_core::windows_file::atomic_write_machine_private(&path, bytes, replace)?;
            } else {
                aegis_core::windows_file::atomic_write_private(&path, bytes, replace, false)?;
            }
            Ok(())
        }
        #[cfg(not(windows))]
        {
            if replace {
                validate_file(&fs::symlink_metadata(&path)?)?;
            }
            let mut staging = tempfile::NamedTempFile::new_in(&self.directory)?;
            staging.write_all(bytes)?;
            staging.as_file().sync_all()?;
            if replace {
                staging.persist(path).map_err(|error| error.error)?;
            } else {
                staging
                    .persist_noclobber(path)
                    .map_err(|error| error.error)?;
            }
            File::open(&self.directory)?.sync_all()?;
            Ok(())
        }
    }

    fn record(&self) -> Result<Record> {
        let record: Record = serde_json::from_slice(&self.read("identity.json")?)
            .context("device enrollment state is invalid")?;
        registry::validate_device_id(&record.device_id)?;
        ensure!(
            record.version == 1
                && matches!(record.phase.as_str(), "initializing" | "prepared" | "ready"),
            "unsupported device enrollment state"
        );
        Ok(record)
    }

    fn save_record(&self, record: &Record, replace: bool) -> Result<()> {
        self.save("identity.json", &serde_json::to_vec(record)?, replace)
    }

    fn create_key(&self, bytes: &[u8]) -> Result<()> {
        // A secret staging filename could survive SIGKILL and be mistaken for
        // an absent key on resume. Create the final key exactly once instead.
        // An interrupted partial key fails validation and needs explicit
        // recovery; it never triggers generation of a replacement identity.
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
        }
        #[cfg(not(windows))]
        let mut key = options.open(self.path("device.key"))?;
        #[cfg(windows)]
        let mut key = if self.machine {
            aegis_core::windows_file::create_machine_private_file(&self.path("device.key"))?
        } else {
            aegis_core::windows_file::create_private_file(&self.path("device.key"), false)?
        };
        aegis_core::secret_file::sync_directory(&self.directory)?;
        key.write_all(bytes)?;
        key.sync_all()?;
        Ok(())
    }

    fn status(&self, record: Record) -> Status {
        Status {
            version: 1,
            device_id: record.device_id,
            phase: record.phase,
            csr_path: self.path("device.csr"),
            key_path: self.path("device.key"),
            certificate_path: self.path("device.pem"),
            device_ca_path: self.path("device-ca.pem"),
        }
    }
}

fn create_identity_parents(directory: &Path) -> Result<()> {
    let mut missing = Vec::new();
    let mut ancestor = directory.parent().context("identity parent missing")?;
    while !ancestor.try_exists()? {
        missing.push(ancestor.to_owned());
        ancestor = ancestor.parent().context("identity parent missing")?;
    }
    for path in missing.into_iter().rev() {
        enrollment::trusted_parent(&path)?;
        #[allow(unused_mut)] // Unix sets the creation mode below.
        #[cfg(not(windows))]
        let mut builder = fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        #[cfg(not(windows))]
        let created = builder.create(&path);
        #[cfg(windows)]
        let created = aegis_core::windows_file::create_private_directory(&path, false, false);
        match created {
            Ok(()) => aegis_core::secret_file::sync_directory(
                path.parent().context("identity parent missing")?,
            )?,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error.into()),
        }
        enrollment::trusted_parent(&path.join(".identity-parent-check"))?;
    }
    Ok(())
}

fn sha(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn public_input(path: &Path) -> Result<Vec<u8>> {
    // Public material still needs trusted ownership and bounded non-symlink
    // input. Certificate authenticity is verified independently below.
    enrollment::trusted_parent(path)?;
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        aegis_core::windows_file::reject_reparse_ancestry(path)?;
        options.custom_flags(windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let file = options.open(path)?;
    #[cfg(windows)]
    aegis_core::windows_file::validate_private(&file, true)?;
    let metadata = file.metadata()?;
    ensure!(
        metadata.is_file() && metadata.len() <= MAX_INPUT,
        "public enrollment input must be a bounded regular file"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        // SAFETY: geteuid only reads process identity.
        let uid = unsafe { libc::geteuid() };
        ensure!(
            (metadata.uid() == uid || metadata.uid() == 0)
                && metadata.mode() & 0o022 == 0
                && metadata.nlink() == 1,
            "public enrollment input ownership, links or permissions invalid"
        );
    }
    let mut data = Vec::new();
    file.take(MAX_INPUT + 1).read_to_end(&mut data)?;
    ensure!(
        data.len() as u64 <= MAX_INPUT,
        "public enrollment input exceeds limit"
    );
    ensure!(!data.is_empty(), "empty device enrollment input");
    Ok(data)
}

fn pinned_ca(store: &Store, record: &Record) -> Result<Vec<u8>> {
    let ca = store.read("device-ca.pem")?;
    ensure!(
        sha(&ca) == record.device_ca_sha256,
        "pinned device CA has changed"
    );
    Ok(ca.to_vec())
}

fn validate_prepared(store: &Store, record: &Record) -> Result<()> {
    pinned_ca(store, record)?;
    let key = store.read("device.key")?;
    let expected = enrollment::csr_for_key(
        &record.device_id,
        std::str::from_utf8(&key).context("device key encoding invalid")?,
    )?;
    ensure!(
        store.read("device.csr")?.as_slice() == expected.as_bytes(),
        "device CSR does not match the local key"
    );
    Ok(())
}

fn validate_ready(store: &Store, record: &Record) -> Result<()> {
    validate_prepared(store, record)?;
    let fingerprint = enrollment::validate_device_certificate(
        &record.device_id,
        &store.read("device.pem")?,
        &pinned_ca(store, record)?,
        &store.read("device.key")?,
        registry::unix_now()?,
    )?;
    ensure!(
        record.certificate_sha256.as_deref() == Some(&fingerprint),
        "installed device certificate has changed"
    );
    Ok(())
}

/// Explicit elevated Windows preparation for a LocalSystem service. Never changes
/// ownership/ACLs of an existing user identity or copies an existing private key.
#[cfg(windows)]
pub(super) fn prepare_system(args: &PrepareArgs) -> Result<Status> {
    registry::validate_device_id(&args.device_id)?;
    enrollment::validate_device_ca(&public_input(&args.device_ca)?)?;
    ensure!(
        args.identity_dir.is_absolute()
            && !args
                .identity_dir
                .components()
                .any(|c| matches!(c, Component::ParentDir)),
        "system identity requires an absolute path without parent traversal"
    );
    let mut missing = Vec::new();
    let mut ancestor = args.identity_dir.as_path();
    while !ancestor.try_exists()? {
        missing.push(ancestor.to_owned());
        ancestor = ancestor
            .parent()
            .context("system identity parent missing")?;
    }
    aegis_core::windows_file::trusted_system_directory(ancestor)?;
    for directory in missing.into_iter().rev() {
        aegis_core::windows_file::create_machine_private_directory(&directory)?;
        aegis_core::windows_file::trusted_system_directory(&directory)?;
    }
    prepare(args)
}

pub(super) fn prepare(args: &PrepareArgs) -> Result<Status> {
    registry::validate_device_id(&args.device_id)?;
    let ca = public_input(&args.device_ca)?;
    enrollment::validate_device_ca(&ca)?;
    let store = Store::open(&args.identity_dir, true)?;
    let mut record = match store.record() {
        Ok(record) => record,
        Err(error)
            if error
                .downcast_ref::<std::io::Error>()
                .is_some_and(|error| error.kind() == std::io::ErrorKind::NotFound) =>
        {
            // An unrecorded key is never overwritten or assigned a new identity.
            for entry in fs::read_dir(&store.directory)? {
                ensure!(
                    entry?.file_name() == ".lock",
                    "unrecorded identity files require operator recovery"
                );
            }
            let record = Record {
                version: 1,
                device_id: args.device_id.clone(),
                phase: "initializing".into(),
                device_ca_sha256: sha(&ca),
                certificate_sha256: None,
            };
            store.save_record(&record, false)?;
            record
        }
        Err(error) => return Err(error),
    };
    ensure!(
        record.device_id == args.device_id && record.device_ca_sha256 == sha(&ca),
        "device identity or CA differs from the pending enrollment"
    );
    if record.phase == "initializing" {
        for entry in fs::read_dir(&store.directory)? {
            let name = entry?.file_name();
            ensure!(
                [
                    ".lock",
                    "identity.json",
                    "device-ca.pem",
                    "device.key",
                    "device.csr"
                ]
                .iter()
                .any(|allowed| name == *allowed),
                "interrupted enrollment has unrecognized files; operator recovery is required"
            );
        }
        match store.read("device-ca.pem") {
            Ok(existing) => ensure!(
                existing.as_slice() == ca.as_slice(),
                "pinned device CA has changed"
            ),
            Err(error) if is_missing(&error) => store.save("device-ca.pem", &ca, false)?,
            Err(error) => return Err(error),
        }
        match store.read("device.key") {
            Ok(_) => {}
            Err(error) if is_missing(&error) => {
                ensure!(
                    !store.path("device.csr").try_exists()?
                        && !store.path("device.pem").try_exists()?,
                    "a previous device key is missing; automatic replacement is forbidden"
                );
                let material = enrollment::generate_csr(&record.device_id)?;
                store.create_key(material.private_key_pem.as_bytes())?;
            }
            Err(error) => return Err(error),
        }
        let key = store.read("device.key")?;
        let csr = enrollment::csr_for_key(
            &record.device_id,
            std::str::from_utf8(&key).context("device key encoding invalid")?,
        )?;
        match store.read("device.csr") {
            Ok(existing) => ensure!(
                existing.as_slice() == csr.as_bytes(),
                "device CSR does not match the local key"
            ),
            Err(error) if is_missing(&error) => store.save("device.csr", csr.as_bytes(), false)?,
            Err(error) => return Err(error),
        }
        record.phase = "prepared".into();
        store.save_record(&record, true)?;
    }
    validate_prepared(&store, &record)?;
    if record.phase == "ready" {
        validate_ready(&store, &record)?;
    }
    Ok(store.status(record))
}

fn is_missing(error: &anyhow::Error) -> bool {
    error
        .downcast_ref::<std::io::Error>()
        .is_some_and(|error| error.kind() == std::io::ErrorKind::NotFound)
}

pub(super) fn complete(args: &CompleteArgs) -> Result<Status> {
    let supplied_ca = public_input(&args.device_ca)?;
    let certificate = public_input(&args.certificate)?;
    let store = Store::open(&args.identity_dir, false)?;
    online::ensure_idle(&store)?;
    let mut record = store.record()?;
    ensure!(
        record.phase != "initializing",
        "device enrollment preparation is incomplete"
    );
    validate_prepared(&store, &record)?;
    let ca = pinned_ca(&store, &record)?;
    ensure!(
        supplied_ca == ca,
        "certificate response cannot replace the pinned device CA"
    );
    let fingerprint = enrollment::validate_device_certificate(
        &record.device_id,
        &certificate,
        &ca,
        &store.read("device.key")?,
        registry::unix_now()?,
    )?;
    match store.read("device.pem") {
        Ok(existing) => ensure!(
            existing.as_slice() == certificate.as_slice(),
            "a different certificate is already installed; explicit rotation is required"
        ),
        Err(error) if is_missing(&error) && record.phase == "prepared" => {
            store.save("device.pem", &certificate, false)?
        }
        Err(error) => return Err(error),
    }
    if record.phase == "ready" {
        ensure!(
            record.certificate_sha256.as_deref() == Some(&fingerprint),
            "device certificate record mismatch"
        );
    } else {
        record.phase = "ready".into();
        record.certificate_sha256 = Some(fingerprint);
        store.save_record(&record, true)?;
    }
    Ok(store.status(record))
}

pub(super) fn status(directory: &Path) -> Result<Status> {
    let store = Store::open(directory, false)?;
    let record = store.record()?;
    match record.phase.as_str() {
        "ready" => validate_ready(&store, &record)?,
        "prepared" => validate_prepared(&store, &record)?,
        _ => bail!("device enrollment preparation is incomplete; resume prepare"),
    }
    Ok(store.status(record))
}
