//! Windows file boundary shared by the client and Windows installer.
//! ACLs are checked on the opened handle; reparse points and hard links fail.
use std::{
    ffi::c_void,
    fs::File,
    io::{self, Write},
    mem,
    os::windows::{
        ffi::OsStrExt,
        fs::MetadataExt,
        io::{AsRawHandle, FromRawHandle},
    },
    path::Path,
    ptr,
};
use windows_sys::Win32::{
    Foundation::*,
    Security::{Authorization::*, *},
    Storage::FileSystem::*,
    System::Threading::*,
};

struct Allocation(*mut c_void);
impl Drop for Allocation {
    fn drop(&mut self) {
        unsafe {
            LocalFree(self.0);
        }
    }
}
fn denied() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "Windows private file ACL or link policy rejected",
    )
}
fn wide(path: &Path) -> io::Result<Vec<u16>> {
    let mut result: Vec<u16> = path.as_os_str().encode_wide().collect();
    if result.contains(&0) {
        return Err(denied());
    }
    result.push(0);
    Ok(result)
}
fn sid_string(sid: PSID) -> io::Result<String> {
    let mut value = ptr::null_mut();
    if sid.is_null() || unsafe { ConvertSidToStringSidW(sid, &mut value) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let _memory = Allocation(value.cast());
    let mut size = 0;
    // Windows allocates a terminated SID string (maximum 184 characters).
    while size < 185 && unsafe { *value.add(size) } != 0 {
        size += 1;
    }
    if size == 185 {
        return Err(denied());
    }
    Ok(String::from_utf16_lossy(unsafe {
        std::slice::from_raw_parts(value, size)
    }))
}
pub fn current_sid() -> io::Result<String> {
    let mut token = ptr::null_mut();
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let result = (|| {
        let mut size = 0;
        unsafe {
            GetTokenInformation(token, TokenUser, ptr::null_mut(), 0, &mut size);
        }
        if size == 0 || size > 65536 {
            return Err(denied());
        }
        // TOKEN_USER contains pointers, so retain native alignment.
        let mut storage = vec![0usize; (size as usize).div_ceil(mem::size_of::<usize>())];
        if unsafe {
            GetTokenInformation(
                token,
                TokenUser,
                storage.as_mut_ptr().cast(),
                size,
                &mut size,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        sid_string(unsafe { (*(storage.as_ptr().cast::<TOKEN_USER>())).User.Sid })
    })();
    unsafe {
        CloseHandle(token);
    }
    result
}

/// Reject supplied junction/symlink ancestry before opening; the directory
/// chosen by the operator must itself be protected against concurrent renames.
pub fn reject_reparse_ancestry(path: &Path) -> io::Result<()> {
    if path
        .components()
        .any(|c| matches!(c, std::path::Component::ParentDir))
    {
        return Err(denied());
    }
    for ancestor in path.ancestors().filter(|p| !p.as_os_str().is_empty()) {
        match std::fs::symlink_metadata(ancestor) {
            Ok(meta) if meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 => {
                return Err(denied())
            }
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

pub fn validate_private(file: &File, service_read: bool) -> io::Result<()> {
    let handle = file.as_raw_handle();
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    if unsafe { GetFileInformationByHandle(handle, &mut info) } == 0 {
        return Err(io::Error::last_os_error());
    }
    if info.dwFileAttributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY) != 0
        || info.nNumberOfLinks != 1
    {
        return Err(denied());
    }
    validate_acl(handle, service_read, false, false)
}
/// Machine secrets cannot retain a per-user owner or a LocalService grant.
pub fn validate_machine_private(file: &File) -> io::Result<()> {
    validate_private(file, false)?;
    validate_acl(file.as_raw_handle(), false, false, true)
}

fn validate_acl(
    handle: windows_sys::Win32::Foundation::HANDLE,
    service_read: bool,
    write_only: bool,
    system_only: bool,
) -> io::Result<()> {
    let mut owner = ptr::null_mut();
    let mut acl = ptr::null_mut();
    let mut descriptor = ptr::null_mut();
    let result = unsafe {
        GetSecurityInfo(
            handle,
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            ptr::null_mut(),
            &mut acl,
            ptr::null_mut(),
            &mut descriptor,
        )
    };
    if result != ERROR_SUCCESS {
        return Err(io::Error::from_raw_os_error(result as i32));
    }
    let _memory = Allocation(descriptor);
    let current = current_sid()?;
    let owner = sid_string(owner)?;
    // Windows owns the volume root through TrustedInstaller. It is part of
    // the operating-system trust boundary, not an ordinary service principal.
    const TRUSTED_INSTALLER: &str =
        "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464";
    if (owner != current || system_only)
        && owner != "S-1-5-18"
        && owner != "S-1-5-32-544"
        && !(write_only && owner == TRUSTED_INSTALLER)
    {
        return Err(denied());
    }
    if acl.is_null() {
        return Err(denied());
    }
    let count = unsafe { (*acl).AceCount };
    for index in 0..count {
        let mut raw = ptr::null_mut();
        if unsafe { GetAce(acl, index as u32, &mut raw) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let header = unsafe { &*raw.cast::<ACE_HEADER>() };
        // Inherit-only entries do not grant access to this file.
        if header.AceFlags & INHERIT_ONLY_ACE as u8 != 0 {
            continue;
        }
        // ACCESS_ALLOWED_ACE_TYPE=0, ACCESS_DENIED_ACE_TYPE=1 (winnt.h).
        if header.AceType == 1 {
            continue;
        }
        if header.AceType != 0 {
            return Err(denied());
        }
        let ace = unsafe { &*raw.cast::<ACCESS_ALLOWED_ACE>() };
        let sid = sid_string((&ace.SidStart as *const u32).cast_mut().cast())?;
        // A system-owned config may grant read access to LocalService. It may
        // not grant that service replacement, ACL changes or secret writes.
        let readonly = FILE_GENERIC_READ | FILE_GENERIC_EXECUTE;
        if service_read && sid == "S-1-5-19" {
            if ace.Mask & !readonly != 0 {
                return Err(denied());
            }
            continue;
        }
        if (sid == current && !system_only)
            || sid == "S-1-5-18"
            || sid == "S-1-5-32-544"
            || write_only && sid == TRUSTED_INSTALLER
        {
            continue;
        }
        // Creating a different child (e.g. Users at C:\) cannot replace an
        // existing protected child. Delete-child and ACL/owner changes can.
        let writes =
            GENERIC_ALL | GENERIC_WRITE | DELETE | WRITE_DAC | WRITE_OWNER | FILE_DELETE_CHILD;
        if ace.Mask & if write_only { writes } else { u32::MAX } != 0 {
            return Err(denied());
        }
    }
    Ok(())
}

pub fn trusted_directory(path: &Path) -> io::Result<()> {
    checked_directory(path, false)
}
pub fn trusted_system_directory(path: &Path) -> io::Result<()> {
    checked_directory(path, true)
}
fn checked_directory(path: &Path, system_only: bool) -> io::Result<()> {
    use std::os::windows::fs::OpenOptionsExt;
    reject_reparse_ancestry(path)?;
    let absolute = path.canonicalize()?;
    for ancestor in absolute.ancestors() {
        let file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
            .open(ancestor)?;
        if !file.metadata()?.is_dir() {
            return Err(denied());
        }
        validate_acl(file.as_raw_handle(), true, true, system_only)?;
    }
    Ok(())
}

/// Protected staging, flushed contents, same-volume write-through replacement.
pub fn atomic_write_private(
    path: &Path,
    bytes: &[u8],
    replace: bool,
    system: bool,
) -> io::Result<()> {
    atomic_write_with_acl(
        path,
        bytes,
        replace,
        PrivateAcl::from_service(system, false),
    )
}

/// Machine-owned secrets readable only by SYSTEM and Administrators, not LocalService.
pub fn atomic_write_machine_private(path: &Path, bytes: &[u8], replace: bool) -> io::Result<()> {
    atomic_write_with_acl(path, bytes, replace, PrivateAcl::Machine)
}

fn atomic_write_with_acl(
    path: &Path,
    bytes: &[u8],
    replace: bool,
    acl: PrivateAcl,
) -> io::Result<()> {
    use std::io::Write;
    reject_reparse_ancestry(path)?;
    let parent = path.parent().ok_or_else(denied)?;
    if matches!(acl, PrivateAcl::Machine) {
        trusted_system_directory(parent)?;
    } else {
        trusted_directory(parent)?;
    }
    if replace {
        match File::open(path) {
            Ok(file) => {
                if matches!(acl, PrivateAcl::Machine) {
                    validate_machine_private(&file)?;
                } else {
                    validate_private(&file, true)?;
                }
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
    }
    let staging = parent.join(format!(".aegis-{:032x}.tmp", rand::random::<u128>()));
    let result = (|| {
        let mut file = create_file_with_acl(&staging, acl)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        let flags = MOVEFILE_WRITE_THROUGH
            | if replace {
                MOVEFILE_REPLACE_EXISTING
            } else {
                0
            };
        if unsafe { MoveFileExW(wide(&staging)?.as_ptr(), wide(path)?.as_ptr(), flags) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&staging);
    }
    result
}

#[derive(Clone, Copy)]
enum PrivateAcl {
    User,
    Service { writable: bool },
    Machine,
}
impl PrivateAcl {
    fn from_service(system: bool, writable: bool) -> Self {
        if system {
            Self::Service { writable }
        } else {
            Self::User
        }
    }
}
fn descriptor(acl: PrivateAcl) -> io::Result<Allocation> {
    let owner = if matches!(acl, PrivateAcl::User) {
        current_sid()?
    } else {
        "BA".to_string()
    };
    let service = match acl {
        PrivateAcl::Service { writable: true } => "(A;OICI;FA;;;LS)",
        PrivateAcl::Service { writable: false } => "(A;OICI;GRGX;;;LS)",
        _ => "",
    };
    let sddl =
        format!("O:{owner}D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;{owner}){service}");
    let sddl: Vec<u16> = sddl.encode_utf16().chain(Some(0)).collect();
    let mut result = ptr::null_mut();
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            1,
            &mut result,
            ptr::null_mut(),
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(Allocation(result))
}

pub fn create_private_directory(path: &Path, system: bool, service_write: bool) -> io::Result<()> {
    create_directory_with_acl(path, PrivateAcl::from_service(system, service_write))
}

/// New machine identity directory; existing directories are never adopted or re-ACLed.
pub fn create_machine_private_directory(path: &Path) -> io::Result<()> {
    create_directory_with_acl(path, PrivateAcl::Machine)
}
fn create_directory_with_acl(path: &Path, acl: PrivateAcl) -> io::Result<()> {
    reject_reparse_ancestry(path)?;
    let descriptor = descriptor(acl)?;
    let attributes = SECURITY_ATTRIBUTES {
        nLength: mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor.0,
        bInheritHandle: 0,
    };
    if unsafe { CreateDirectoryW(wide(path)?.as_ptr(), &attributes) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Creates a new file with its final ACL before writing any secret bytes.
pub fn write_private_new(path: &Path, bytes: &[u8], system: bool) -> io::Result<()> {
    let mut file = create_private_file(path, system)?;
    file.write_all(bytes)?;
    file.sync_all()
}

pub fn create_private_file(path: &Path, system: bool) -> io::Result<File> {
    create_file_with_acl(path, PrivateAcl::from_service(system, false))
}

/// Create a machine-owned secret with no LocalService grant before writing bytes.
pub fn create_machine_private_file(path: &Path) -> io::Result<File> {
    create_file_with_acl(path, PrivateAcl::Machine)
}
fn create_file_with_acl(path: &Path, acl: PrivateAcl) -> io::Result<File> {
    reject_reparse_ancestry(path)?;
    let descriptor = descriptor(acl)?;
    let attributes = SECURITY_ATTRIBUTES {
        nLength: mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor.0,
        bInheritHandle: 0,
    };
    let handle = unsafe {
        CreateFileW(
            wide(path)?.as_ptr(),
            GENERIC_READ | GENERIC_WRITE | DELETE | READ_CONTROL,
            FILE_SHARE_READ | FILE_SHARE_DELETE,
            &attributes,
            CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
            ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    let file = unsafe { File::from_raw_handle(handle) };
    if matches!(acl, PrivateAcl::Machine) {
        validate_machine_private(&file)?;
    } else {
        validate_private(&file, matches!(acl, PrivateAcl::Service { .. }))?;
    }
    Ok(file)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn world_readable_acl_is_rejected_on_open_handle() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("unsafe-key");
        write_private_new(&path, b"synthetic", false).unwrap();
        let sddl: Vec<u16> = "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;GR;;;WD)"
            .encode_utf16()
            .chain(Some(0))
            .collect();
        let mut descriptor = ptr::null_mut();
        assert_ne!(
            unsafe {
                ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    sddl.as_ptr(),
                    1,
                    &mut descriptor,
                    ptr::null_mut(),
                )
            },
            0
        );
        let _memory = Allocation(descriptor);
        let mut acl = ptr::null_mut();
        let mut present = 0;
        let mut defaulted = 0;
        assert_ne!(
            unsafe {
                GetSecurityDescriptorDacl(descriptor, &mut present, &mut acl, &mut defaulted)
            },
            0
        );
        assert_eq!(
            unsafe {
                SetNamedSecurityInfoW(
                    wide(&path).unwrap().as_ptr(),
                    SE_FILE_OBJECT,
                    DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                    ptr::null_mut(),
                    ptr::null_mut(),
                    acl,
                    ptr::null(),
                )
            },
            0
        );
        let file = File::open(&path).unwrap();
        assert!(validate_private(&file, false).is_err());
        assert!(validate_private(&file, true).is_err());
    }
    #[test]
    fn private_file_roundtrip_and_hardlink_rejection() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("key");
        write_private_new(&path, b"synthetic", false).unwrap();
        let file = File::open(&path).unwrap();
        validate_private(&file, false).unwrap();
        std::fs::hard_link(&path, root.path().join("alias")).unwrap();
        assert!(validate_private(&file, false).is_err());
    }
    #[test]
    fn private_writer_never_replaces_existing_file() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("key");
        write_private_new(&path, b"first", false).unwrap();
        assert!(write_private_new(&path, b"second", false).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"first");
    }
}
