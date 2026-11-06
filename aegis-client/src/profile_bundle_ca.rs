//! Versioned, private staging of one explicitly bundled public MASQUE CA.
//! This action does not select trust policy or inspect installed credentials.
use std::path::PathBuf;

#[derive(clap::Args, Clone, Debug)]
pub struct Args {
    #[command(subcommand)]
    action: Action,
}

#[derive(clap::Subcommand, Clone, Debug)]
enum Action {
    Version,
    Prepare {
        #[arg(long)]
        bundle_root: PathBuf,
        #[arg(long)]
        stage_root: PathBuf,
        #[arg(long)]
        config_dir: PathBuf,
        #[arg(long)]
        owner_uid: u32,
        /// The caller will run its existing explicit reinstall purge before Install.
        #[arg(long)]
        purge_existing: bool,
    },
    Install {
        #[arg(long)]
        stage_root: PathBuf,
        #[arg(long)]
        config_dir: PathBuf,
        #[arg(long)]
        owner_uid: u32,
    },
}

pub(super) fn run(args: &Args) -> Result<(), String> {
    let result = match &args.action {
        Action::Version => {
            println!("bundle-ca-v1");
            return Ok(());
        }
        Action::Prepare {
            bundle_root,
            stage_root,
            config_dir,
            owner_uid,
            purge_existing,
        } => prepare(
            bundle_root,
            stage_root,
            config_dir,
            *owner_uid,
            *purge_existing,
        ),
        Action::Install {
            stage_root,
            config_dir,
            owner_uid,
        } => install(stage_root, config_dir, *owner_uid),
    };
    // TOML, paths, certificates and underlying errors never cross stdout/stderr.
    result.map_err(|_| "Private bundled MASQUE CA operation refused".to_string())
}

#[cfg(not(unix))]
fn prepare(
    _: &std::path::Path,
    _: &std::path::Path,
    _: &std::path::Path,
    _: u32,
    _: bool,
) -> std::io::Result<()> {
    Err(std::io::ErrorKind::Unsupported.into())
}
#[cfg(not(unix))]
fn install(_: &std::path::Path, _: &std::path::Path, _: u32) -> std::io::Result<()> {
    Err(std::io::ErrorKind::Unsupported.into())
}

#[cfg(unix)]
use unix::{install, prepare};

#[cfg(unix)]
mod unix {
    use rustls::pki_types::{pem::PemObject, CertificateDer};
    use std::fs::{self, OpenOptions};
    use std::io::{self, Read, Write};
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
    use std::path::{Component, Path};
    use zeroize::Zeroizing;

    const BYTE_CAP: u64 = 4 * 1024 * 1024;
    fn refused() -> io::Error {
        io::Error::other("bundled public CA refused")
    }
    fn uid() -> u32 {
        // SAFETY: geteuid reads identity and has no pointer arguments.
        unsafe { libc::geteuid() }
    }
    fn path_shape(path: &Path) -> io::Result<()> {
        if !path.is_absolute()
            || path
                .components()
                .any(|c| matches!(c, Component::ParentDir | Component::CurDir))
        {
            return Err(refused());
        }
        Ok(())
    }
    fn ancestry(path: &Path, owner: u32, missing: bool, private: bool) -> io::Result<()> {
        path_shape(path)?;
        if uid() != 0 && uid() != owner {
            return Err(refused());
        }
        for ancestor in path.ancestors() {
            let metadata = match fs::symlink_metadata(ancestor) {
                Ok(metadata) => metadata,
                Err(error) if missing && error.kind() == io::ErrorKind::NotFound => continue,
                Err(error) => return Err(error),
            };
            let sticky_root = metadata.uid() == 0 && metadata.mode() & 0o1000 != 0;
            if !metadata.is_dir()
                || ![0, uid(), owner].contains(&metadata.uid())
                || (metadata.mode() & 0o022 != 0 && !sticky_root)
            {
                return Err(refused());
            }
            if ancestor == path && private && metadata.mode() & 0o077 != 0 {
                return Err(refused());
            }
        }
        Ok(())
    }
    fn read_owned(path: &Path) -> io::Result<Zeroizing<Vec<u8>>> {
        let parent = path.parent().ok_or_else(refused)?;
        // Reuse the existing trusted read-parent policy, then disallow aliases.
        aegis_core::secret_file::trusted_read_parent(path)?;
        ancestry(parent, uid(), false, false)?;
        let private_boundary = parent.ancestors().any(|ancestor| {
            fs::symlink_metadata(ancestor)
                .is_ok_and(|m| m.is_dir() && m.uid() == uid() && m.mode() & 0o077 == 0)
        });
        if !private_boundary {
            return Err(refused());
        }
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)?;
        let metadata = file.metadata()?;
        if !metadata.is_file()
            || metadata.nlink() != 1
            || ![0, uid()].contains(&metadata.uid())
            || metadata.mode() & 0o022 != 0
            || metadata.len() > BYTE_CAP
        {
            return Err(refused());
        }
        let mut bytes = Zeroizing::new(Vec::new());
        file.take(BYTE_CAP + 1).read_to_end(&mut bytes)?;
        if bytes.len() as u64 > BYTE_CAP {
            return Err(refused());
        }
        Ok(bytes)
    }
    fn typed(bytes: &[u8]) -> io::Result<aegis_core::Settings> {
        toml::from_str(std::str::from_utf8(bytes).map_err(|_| refused())?).map_err(|_| refused())
    }
    fn validate_ca(bytes: &[u8]) -> io::Result<()> {
        let mut roots = rustls::RootCertStore::empty();
        for cert in CertificateDer::pem_slice_iter(bytes) {
            roots
                .add(cert.map_err(|_| refused())?)
                .map_err(|_| refused())?;
        }
        if roots.is_empty() {
            return Err(refused());
        }
        Ok(())
    }
    fn target(config_dir: &Path, owner: u32, missing: bool) -> io::Result<std::path::PathBuf> {
        ancestry(config_dir, owner, missing, !missing)?;
        let target = config_dir.join("masque-ca.pem");
        if target.to_str().is_none() {
            return Err(refused());
        }
        Ok(target)
    }
    fn remove_created(path: &Path, dev: u64, ino: u64) -> io::Result<()> {
        let m = fs::symlink_metadata(path)?;
        if !m.is_file() || m.dev() != dev || m.ino() != ino || m.nlink() != 1 {
            return Err(refused());
        }
        fs::remove_file(path)
    }
    fn write_new(path: &Path, bytes: &[u8]) -> io::Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)?;
        let metadata = file.metadata()?;
        let result = file.write_all(bytes).and_then(|_| file.sync_all());
        drop(file);
        let result =
            result.and_then(|_| fs::File::open(path.parent().ok_or_else(refused)?)?.sync_all());
        if let Err(error) = result {
            // Retain unknown replacement bytes instead of deleting through them.
            remove_created(path, metadata.dev(), metadata.ino())?;
            return Err(error);
        }
        Ok(())
    }
    fn remove_stage(path: &Path, dev: u64, ino: u64) -> io::Result<()> {
        let metadata = fs::symlink_metadata(path)?;
        if !metadata.is_dir() || metadata.dev() != dev || metadata.ino() != ino {
            return Err(refused());
        }
        let entries = fs::read_dir(path)?.collect::<Result<Vec<_>, _>>()?;
        for entry in &entries {
            if !["aegis-client.toml", "masque-ca.pem"]
                .iter()
                .any(|name| entry.file_name() == *name)
            {
                return Err(refused());
            }
            let m = fs::symlink_metadata(entry.path())?;
            if !m.is_file() || m.nlink() != 1 || m.uid() != uid() || m.mode() & 0o077 != 0 {
                return Err(refused());
            }
        }
        for entry in entries {
            fs::remove_file(entry.path())?;
        }
        fs::remove_dir(path)
    }
    pub(super) fn prepare(
        bundle_root: &Path,
        stage_root: &Path,
        config_dir: &Path,
        owner: u32,
        purge_existing: bool,
    ) -> io::Result<()> {
        let raw = read_owned(&bundle_root.join("aegis-client.toml"))?;
        let settings = typed(&raw)?;
        let scoped = settings
            .relay
            .masque_ca_cert
            .as_deref()
            .is_some_and(|path| {
                matches!(
                    path.to_str(),
                    Some("masque-ca.pem" | "./masque-ca.pem" | "__CLIENT_MASQUE_CA_CERT_PATH__")
                )
            });
        // Absence and external CA references remain byte-exact, including mode.
        let (config, ca) = if scoped {
            let installed_ca = target(config_dir, owner, true)?;
            match fs::symlink_metadata(&installed_ca) {
                Ok(metadata) => {
                    if !purge_existing
                        || !metadata.is_file()
                        || metadata.nlink() != 1
                        || ![0, uid(), owner].contains(&metadata.uid())
                        || metadata.mode() & 0o077 != 0
                    {
                        return Err(refused());
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error),
            }
            let ca = read_owned(&bundle_root.join("masque-ca.pem"))?;
            validate_ca(&ca)?;
            let mut value: toml::Value =
                toml::from_str(std::str::from_utf8(&raw).map_err(|_| refused())?)
                    .map_err(|_| refused())?;
            let relay = value
                .get_mut("relay")
                .and_then(toml::Value::as_table_mut)
                .ok_or_else(refused)?;
            relay.insert(
                "masque_ca_cert".into(),
                toml::Value::String(installed_ca.to_str().ok_or_else(refused)?.into()),
            );
            let config =
                Zeroizing::new(toml::to_string(&value).map_err(|_| refused())?.into_bytes());
            // Typed roundtrip prevents changing any other serialized field.
            let mut expected = toml::Value::try_from(settings).map_err(|_| refused())?;
            expected
                .get_mut("relay")
                .and_then(toml::Value::as_table_mut)
                .ok_or_else(refused)?
                .insert(
                    "masque_ca_cert".into(),
                    toml::Value::String(installed_ca.to_str().ok_or_else(refused)?.into()),
                );
            if toml::Value::try_from(typed(&config)?).map_err(|_| refused())? != expected {
                return Err(refused());
            }
            (config, Some(ca))
        } else {
            (raw, None)
        };
        ancestry(
            stage_root.parent().ok_or_else(refused)?,
            uid(),
            false,
            false,
        )?;
        path_shape(stage_root)?;
        fs::DirBuilder::new().mode(0o700).create(stage_root)?;
        let metadata = fs::symlink_metadata(stage_root)?;
        let result = (|| {
            write_new(&stage_root.join("aegis-client.toml"), &config)?;
            if let Some(ca) = ca {
                write_new(&stage_root.join("masque-ca.pem"), &ca)?;
            }
            Ok(())
        })();
        if let Err(error) = result {
            remove_stage(stage_root, metadata.dev(), metadata.ino())?;
            return Err(error);
        }
        Ok(())
    }
    pub(super) fn install(stage_root: &Path, config_dir: &Path, owner: u32) -> io::Result<()> {
        ancestry(stage_root, uid(), false, true)?;
        let source = stage_root.join("masque-ca.pem");
        match fs::symlink_metadata(&source) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error),
            Ok(_) => {}
        }
        let target = target(config_dir, owner, false)?;
        let settings = typed(&read_owned(&stage_root.join("aegis-client.toml"))?)?;
        if settings.relay.masque_ca_cert.as_deref() != Some(target.as_path()) {
            return Err(refused());
        }
        let ca = read_owned(&source)?;
        validate_ca(&ca)?;
        write_new(&target, &ca)
    }
}

#[cfg(all(test, unix))]
#[path = "profile_bundle_ca_tests.rs"]
mod tests;
