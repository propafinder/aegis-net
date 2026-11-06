//! Reviewed adapter entry bytes held across a child invocation. This does not
//! seal the adapter's imports, child tools or provider service implementation.
use super::{invalid, WinctlError, MAX_BINARY};
use sha2::{Digest, Sha256};
use std::{
    fs::{File, OpenOptions},
    io::{self, Read, Seek, SeekFrom},
    os::windows::{fs::OpenOptionsExt, io::AsRawHandle},
    path::{Path, PathBuf},
};
use windows_sys::Win32::Storage::FileSystem::{
    GetFileInformationByHandle, GetFinalPathNameByHandleW, BY_HANDLE_FILE_INFORMATION,
    FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS,
    FILE_FLAG_OPEN_REPARSE_POINT, FILE_LIST_DIRECTORY, FILE_READ_ATTRIBUTES, FILE_SHARE_READ,
    FILE_SHARE_WRITE,
};

#[derive(PartialEq, Eq)]
struct Identity {
    volume: u32,
    index: u64,
    attributes: u32,
    links: u32,
    size: u64,
    written: u64,
}
fn identity(file: &File, directory: bool) -> Result<Identity, WinctlError> {
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) } == 0 {
        return Err(io::Error::last_os_error().into());
    }
    if info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0) != directory
        || !directory && info.nNumberOfLinks != 1
    {
        return Err(invalid());
    }
    Ok(Identity {
        volume: info.dwVolumeSerialNumber,
        index: (u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow),
        attributes: info.dwFileAttributes,
        // Unrelated child creation may change directory size/mtime; the bound
        // directory's volume/index/path/attributes remain the custody identity.
        links: if directory { 0 } else { info.nNumberOfLinks },
        size: if directory {
            0
        } else {
            (u64::from(info.nFileSizeHigh) << 32) | u64::from(info.nFileSizeLow)
        },
        written: if directory {
            0
        } else {
            (u64::from(info.ftLastWriteTime.dwHighDateTime) << 32)
                | u64::from(info.ftLastWriteTime.dwLowDateTime)
        },
    })
}
fn named_path(file: &File) -> Result<PathBuf, WinctlError> {
    let mut buffer = vec![0u16; 32768];
    let length = unsafe {
        GetFinalPathNameByHandleW(
            file.as_raw_handle(),
            buffer.as_mut_ptr(),
            buffer.len() as u32,
            0,
        )
    };
    if length == 0 || length as usize >= buffer.len() {
        return Err(invalid());
    }
    let name = String::from_utf16(&buffer[..length as usize]).map_err(|_| invalid())?;
    Ok(PathBuf::from(
        name.strip_prefix(r"\\?\").ok_or_else(invalid)?,
    ))
}
fn open(path: &Path, directory: bool) -> Result<File, WinctlError> {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    if directory {
        options
            .access_mode(FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS);
    } else {
        options.share_mode(FILE_SHARE_READ);
    }
    let file = options.open(path)?;
    identity(&file, directory)?;
    if named_path(&file)?.as_os_str() != path.as_os_str() {
        return Err(invalid());
    }
    Ok(file)
}

pub(super) struct AdapterLease {
    path: PathBuf,
    file: File,
    original: Identity,
    directories: Vec<(PathBuf, File, Identity)>,
    pin: String,
}
impl AdapterLease {
    pub(super) fn acquire(path: &Path, pin: &str) -> Result<Self, WinctlError> {
        let text = path.to_str().ok_or_else(invalid)?;
        let bytes = text.as_bytes();
        if bytes.len() < 3
            || !bytes[0].is_ascii_alphabetic()
            || bytes[1..3] != *b":\\"
            || text.contains('/')
            || text[2..].contains(':')
            || std::path::absolute(path)?.as_os_str() != path.as_os_str()
            || pin.len() != 64
            || !pin.bytes().all(|b| b.is_ascii_hexdigit())
            || !matches!(
                path.extension()
                    .and_then(|v| v.to_str())
                    .map(str::to_ascii_lowercase)
                    .as_deref(),
                Some("ps1" | "exe")
            )
        {
            return Err(invalid());
        }
        aegis_core::windows_file::reject_reparse_ancestry(path)?;
        let mut parents: Vec<_> = path
            .parent()
            .ok_or_else(invalid)?
            .ancestors()
            .map(Path::to_path_buf)
            .collect();
        parents.reverse();
        let directories = parents
            .into_iter()
            .map(|parent| {
                let directory = open(&parent, true)?;
                let bound = identity(&directory, true)?;
                Ok((parent, directory, bound))
            })
            .collect::<Result<Vec<_>, WinctlError>>()?;
        let file = open(path, false)?;
        let original = identity(&file, false)?;
        let lease = Self {
            path: path.to_path_buf(),
            file,
            original,
            directories,
            pin: pin.to_ascii_lowercase(),
        };
        lease.verify()?;
        Ok(lease)
    }
    pub(super) fn verify(&self) -> Result<(), WinctlError> {
        for (path, file, original) in &self.directories {
            if identity(file, true)? != *original
                || named_path(file)?.as_os_str() != path.as_os_str()
            {
                return Err(invalid());
            }
        }
        if identity(&self.file, false)? != self.original
            || self.original.size > MAX_BINARY
            || named_path(&self.file)?.as_os_str() != self.path.as_os_str()
        {
            return Err(invalid());
        }
        let mut stream = &self.file;
        stream.seek(SeekFrom::Start(0))?;
        let mut digest = Sha256::new();
        let mut buffer = [0u8; 65536];
        let mut total = 0u64;
        loop {
            let count = stream.read(&mut buffer)?;
            if count == 0 {
                break;
            }
            total = total.checked_add(count as u64).ok_or_else(invalid)?;
            if total > MAX_BINARY {
                return Err(invalid());
            }
            digest.update(&buffer[..count]);
        }
        if format!("{:x}", digest.finalize()) != self.pin
            || total != self.original.size
            || identity(&self.file, false)? != self.original
        {
            return Err(invalid());
        }
        if identity(&open(&self.path, false)?, false)? != self.original {
            return Err(invalid());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::super::hash;
    use super::*;
    fn fixture() -> (tempfile::TempDir, PathBuf, String) {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("entry.ps1");
        std::fs::write(&path, b"throw 'inert entry never invoked'\n").unwrap();
        let name = std::fs::canonicalize(&path).unwrap();
        let name = name.to_str().unwrap().strip_prefix(r"\\?\").unwrap();
        let path = PathBuf::from(name);
        let pin = hash(&std::fs::read(&path).unwrap());
        (directory, path, pin)
    }
    #[test]
    fn entry_pin_and_canonical_path_refuse_before_invocation() {
        let (_directory, path, pin) = fixture();
        assert!(AdapterLease::acquire(&path, &"0".repeat(64)).is_err());
        assert!(AdapterLease::acquire(Path::new("entry.ps1"), &pin).is_err());
        assert!(AdapterLease::acquire(
            Path::new(&format!("{}:alternate.ps1", path.display())),
            &pin
        )
        .is_err());
        let alias = path
            .parent()
            .unwrap()
            .join("..")
            .join(path.parent().unwrap().file_name().unwrap())
            .join("entry.ps1");
        assert!(AdapterLease::acquire(&alias, &pin).is_err());
    }
    #[test]
    fn held_entry_denies_write_delete_replace_and_ancestor_rename() {
        let (_directory, path, pin) = fixture();
        let lease = AdapterLease::acquire(&path, &pin).unwrap();
        assert!(OpenOptions::new().write(true).open(&path).is_err());
        assert!(std::fs::remove_file(&path).is_err());
        let replacement = path.with_file_name("replacement.ps1");
        std::fs::write(&replacement, b"different entry\n").unwrap();
        assert!(std::fs::rename(&replacement, &path).is_err());
        assert!(std::fs::rename(
            path.parent().unwrap(),
            path.parent().unwrap().with_extension("moved")
        )
        .is_err());
        lease.verify().unwrap();
        drop(lease);
        std::fs::write(&path, b"changed after release\n").unwrap();
        assert!(AdapterLease::acquire(&path, &pin).is_err());
    }
    #[test]
    fn hardlinked_adapter_entry_is_refused() {
        let (_directory, path, pin) = fixture();
        std::fs::hard_link(&path, path.with_file_name("alias.ps1")).unwrap();
        assert!(AdapterLease::acquire(&path, &pin).is_err());
    }
    #[test]
    fn reparse_ancestor_is_refused() {
        use std::os::windows::{fs::MetadataExt, process::CommandExt};
        let (_directory, path, pin) = fixture();
        // Use fixture()'s ordinary canonical spelling for BOTH cmd paths,
        // rather than TempDir's independently spelled/possibly extended path.
        let parent = path.parent().unwrap();
        let junction = parent.join("junction with spaces");
        let bytes = std::fs::read(&path).unwrap();
        let ordinary = AdapterLease::acquire(&path, &pin).unwrap();
        ordinary.verify().unwrap();
        drop(ordinary);
        let command = PathBuf::from(std::env::var_os("SystemRoot").unwrap())
            .join("System32")
            .join("cmd.exe");
        let command_text = command.to_str().unwrap();
        assert!(
            !command_text.contains('/') && command.is_absolute() && command.is_file(),
            "Owned junction fixture cmd image must be an ordinary existing Windows path: {command_text}"
        );
        let junction_text = junction.to_str().unwrap();
        let parent_text = parent.to_str().unwrap();
        for text in [junction_text, parent_text] {
            assert!(
                !text
                    .chars()
                    .any(|c| matches!(c, '"' | '%' | '!' | '^' | '\r' | '\n' | '\0')),
                "Owned junction fixture path contains unsupported cmd syntax"
            );
        }
        // A junction needs no symlink privilege. Only this owned directory is
        // linked, and remove_dir removes the junction entry without recursion.
        // cmd built-in syntax is explicitly quoted; ordinary executable argv
        // escaping is not its grammar. This fixture uses the CI job bound,
        // not a separately claimed per-child execution deadline.
        let cmd_tail = format!("mklink /J \"{junction_text}\" \"{parent_text}\"");
        let output = std::process::Command::new(&command)
            .args(["/D", "/V:OFF", "/C"])
            .raw_arg(&cmd_tail)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "mklink fixture failed: {:?}; image={command_text}; tail={cmd_tail}; stdout={}; stderr={}",
            output.status.code(),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        // A missing entry or an unrelated file must not satisfy the refusal.
        // Retain preconditions, then remove the junction before asserting them.
        let metadata = std::fs::symlink_metadata(&junction);
        let through = std::fs::read(junction.join("entry.ps1"));
        let refused = AdapterLease::acquire(&junction.join("entry.ps1"), &pin).is_err();
        std::fs::remove_dir(&junction).unwrap();
        assert_ne!(
            metadata.unwrap().file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT,
            0
        );
        assert_eq!(through.unwrap(), bytes);
        assert_eq!(std::fs::read(&path).unwrap(), bytes);
        assert!(refused);
    }
}
