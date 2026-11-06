//! Native read-only account discovery. Password/authentication fields are never
//! copied. The OS directory snapshot is not a lock against administrator edits.
use super::worker_ipc::launch_contract::{AccountRecord, LaunchAdmission};
use std::{
    io,
    sync::Mutex,
    time::{Duration, Instant},
};

const MAX_RECORDS: usize = 4096;
const MAX_MEMBERS: usize = 16384;
const MAX_TEXT: usize = 512;
static INVENTORY: Mutex<()> = Mutex::new(());

pub(super) struct VerifiedAccount {
    pub(super) name: String,
    pub(super) admission: LaunchAdmission,
}

#[derive(Clone)]
struct GroupRecord {
    name: String,
    gid: u32,
    members: Vec<String>,
}

fn denied() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "dedicated native worker account rejected",
    )
}

fn validate_groups(
    accounts: &[AccountRecord],
    groups: &[GroupRecord],
    name: &str,
) -> io::Result<LaunchAdmission> {
    if groups.is_empty()
        || groups.len() > MAX_RECORDS
        || groups.iter().map(|g| g.members.len()).sum::<usize>() > MAX_MEMBERS
    {
        return Err(denied());
    }
    let admission = LaunchAdmission::from_inventory(accounts, name)?;
    let (_, gid) = admission.ids();
    let matching: Vec<_> = groups.iter().filter(|g| g.gid == gid).collect();
    if matching.len() != 1
        || matching[0].name != name
        || matching[0].members.iter().any(|member| member != name)
        || groups
            .iter()
            .any(|g| g.gid != gid && g.members.iter().any(|member| member == name))
        || groups.iter().filter(|g| g.name == name).count() != 1
    {
        return Err(denied());
    }
    Ok(admission)
}

/// Libc owns this NUL-terminated record until the next same-thread directory
/// operation. Copy only bounded public fields while that record remains live.
unsafe fn public_text(pointer: *const libc::c_char) -> io::Result<String> {
    if pointer.is_null() {
        return Err(denied());
    }
    // strnlen bounds scanning of native directory records; libc guarantees a
    // valid string allocation. Never inspect pw_passwd/gr_passwd.
    let length = unsafe { libc::strnlen(pointer, MAX_TEXT + 1) };
    if length == 0 || length > MAX_TEXT {
        return Err(denied());
    }
    let bytes = unsafe { std::slice::from_raw_parts(pointer.cast::<u8>(), length) };
    let value = std::str::from_utf8(bytes).map_err(|_| denied())?;
    if value.bytes().any(|b| b < 0x20 || b == 0x7f) {
        return Err(denied());
    }
    Ok(value.to_owned())
}

fn bounded(deadline: Instant, count: usize) -> io::Result<()> {
    if count >= MAX_RECORDS || Instant::now() >= deadline {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "native worker inventory budget exceeded",
        ));
    }
    Ok(())
}

// Read only public native fields, even if a packed record is unaligned.
unsafe fn account_fields(
    pointer: *const libc::passwd,
) -> (*mut libc::c_char, u32, u32, *mut libc::c_char) {
    unsafe {
        (
            std::ptr::addr_of!((*pointer).pw_name).read_unaligned(),
            std::ptr::addr_of!((*pointer).pw_uid).read_unaligned(),
            std::ptr::addr_of!((*pointer).pw_gid).read_unaligned(),
            std::ptr::addr_of!((*pointer).pw_shell).read_unaligned(),
        )
    }
}
unsafe fn group_fields(
    pointer: *const libc::group,
) -> (*mut libc::c_char, u32, *mut *mut libc::c_char) {
    unsafe {
        (
            std::ptr::addr_of!((*pointer).gr_name).read_unaligned(),
            std::ptr::addr_of!((*pointer).gr_gid).read_unaligned(),
            std::ptr::addr_of!((*pointer).gr_mem).read_unaligned(),
        )
    }
}

struct DirectoryHandles;
impl Drop for DirectoryHandles {
    fn drop(&mut self) {
        // Same-thread libc iterators, serialized for this module and always
        // closed on parse/error paths. Apple documents thread-specific storage.
        unsafe {
            libc::endpwent();
            libc::endgrent();
        }
    }
}

unsafe fn copy_group_members(
    pointer: *const *mut libc::c_char,
    count: &mut usize,
) -> io::Result<Vec<String>> {
    if pointer.is_null() {
        return Err(denied());
    }
    let mut members = Vec::new();
    for index in 0..=MAX_MEMBERS {
        // Darwin libinfo can pack the native member array without Rust's
        // pointer alignment. Never form an aligned reference to this storage.
        let member = unsafe { std::ptr::read_unaligned(pointer.add(index)) };
        if member.is_null() {
            break;
        }
        if *count >= MAX_MEMBERS {
            return Err(denied());
        }
        members.push(unsafe { public_text(member) }?);
        *count += 1;
    }
    Ok(members)
}

pub(super) fn discover(name: &str) -> io::Result<VerifiedAccount> {
    // A second caller may not wait indefinitely behind a native directory call.
    let _guard = INVENTORY.try_lock().map_err(|_| denied())?;
    let deadline = Instant::now() + Duration::from_secs(3);
    let _handles = DirectoryHandles;
    unsafe {
        libc::setpwent();
        libc::setgrent();
    }
    let mut accounts = Vec::new();
    loop {
        bounded(deadline, accounts.len())?;
        unsafe {
            *libc::__error() = 0;
        }
        let pointer = unsafe { libc::getpwent() };
        if pointer.is_null() {
            if unsafe { *libc::__error() } != 0 {
                return Err(io::Error::last_os_error());
            }
            break;
        }
        let (native_name, uid, gid, native_shell) = unsafe { account_fields(pointer) };
        let account_name = unsafe { public_text(native_name) }?;
        let non_login = account_name == name
            && matches!(
                unsafe { public_text(native_shell) }?.as_str(),
                "/usr/bin/false" | "/usr/sbin/nologin"
            );
        accounts.push(AccountRecord {
            name: account_name,
            uid,
            gid,
            non_login,
        });
    }
    let mut groups = Vec::new();
    let mut member_count = 0;
    loop {
        bounded(deadline, groups.len())?;
        unsafe {
            *libc::__error() = 0;
        }
        let pointer = unsafe { libc::getgrent() };
        if pointer.is_null() {
            if unsafe { *libc::__error() } != 0 {
                return Err(io::Error::last_os_error());
            }
            break;
        }
        let (native_name, gid, native_members) = unsafe { group_fields(pointer) };
        let group_name = unsafe { public_text(native_name) }?;
        let members = unsafe { copy_group_members(native_members, &mut member_count) }?;
        groups.push(GroupRecord {
            name: group_name,
            gid,
            members,
        });
    }
    let admission = validate_groups(&accounts, &groups, name)?;
    // First-match native lookups are not sufficient for uniqueness. Enumeration
    // above checks sharing; rereading name+UID detects changed selection.
    let c_name = std::ffi::CString::new(name).map_err(|_| denied())?;
    let by_name = unsafe { libc::getpwnam(c_name.as_ptr()) };
    if by_name.is_null() {
        return Err(denied());
    }
    let (native_name, uid, gid, native_shell) = unsafe { account_fields(by_name) };
    if (uid, gid) != admission.ids()
        || unsafe { public_text(native_name) }? != name
        || !matches!(
            unsafe { public_text(native_shell) }?.as_str(),
            "/usr/bin/false" | "/usr/sbin/nologin"
        )
    {
        return Err(denied());
    }
    let by_uid = unsafe { libc::getpwuid(admission.ids().0) };
    if by_uid.is_null() || unsafe { public_text(account_fields(by_uid).0) }? != name {
        return Err(denied());
    }
    Ok(VerifiedAccount {
        name: name.to_owned(),
        admission,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn accounts() -> Vec<AccountRecord> {
        vec![AccountRecord {
            name: "_aegis_network".into(),
            uid: 601,
            gid: 601,
            non_login: true,
        }]
    }
    fn group() -> GroupRecord {
        GroupRecord {
            name: "_aegis_network".into(),
            gid: 601,
            members: vec![],
        }
    }
    #[test]
    fn dedicated_native_group_contract_refuses_foreign_members_supplementary_and_duplicate_ids() {
        let name = "_aegis_network";
        assert_eq!(
            validate_groups(&accounts(), &[group()], name)
                .unwrap()
                .ids(),
            (601, 601)
        );
        for variant in 0..6 {
            let mut groups = vec![group()];
            match variant {
                0 => groups.clear(),
                1 => groups[0].members.push("foreign".into()),
                2 => groups.push(group()),
                3 => groups[0].name = "staff".into(),
                4 => groups.push(GroupRecord {
                    name: "staff".into(),
                    gid: 20,
                    members: vec![name.into()],
                }),
                _ => groups = vec![group(); MAX_RECORDS + 1],
            }
            assert!(validate_groups(&accounts(), &groups, name).is_err());
        }
        let mut shared = accounts();
        shared.push(AccountRecord {
            name: "foreign".into(),
            uid: 602,
            gid: 601,
            non_login: true,
        });
        assert!(validate_groups(&shared, &[group()], name).is_err());
    }
    #[test]
    fn bounded_native_text_and_actual_unknown_account_refuse_without_account_mutation() {
        let good = std::ffi::CString::new("_aegis_network").unwrap();
        assert_eq!(
            unsafe { public_text(good.as_ptr()) }.unwrap(),
            "_aegis_network"
        );
        for bytes in [vec![b'x'; MAX_TEXT + 1], b"name\n".to_vec(), vec![0xff]] {
            let value = std::ffi::CString::new(bytes).unwrap();
            assert!(unsafe { public_text(value.as_ptr()) }.is_err());
        }
        assert!(unsafe { public_text(std::ptr::null()) }.is_err());
        assert!(discover("_aegis_absent_worker_source_fixture").is_err());
    }

    #[test]
    fn actual_native_member_copy_accepts_unaligned_storage_without_aligned_reference() {
        let text = std::ffi::CString::new("_aegis_network").unwrap();
        let width = std::mem::size_of::<*const libc::c_char>();
        let mut storage = vec![0u8; width * 2 + 1];
        storage[1..1 + width].copy_from_slice(&(text.as_ptr() as usize).to_ne_bytes());
        let pointer = unsafe { storage.as_ptr().add(1).cast::<*mut libc::c_char>() };
        assert_ne!(
            pointer as usize % std::mem::align_of::<*mut libc::c_char>(),
            0
        );
        let mut count = 0;
        assert_eq!(
            unsafe { copy_group_members(pointer, &mut count) }.unwrap(),
            vec!["_aegis_network"]
        );
        assert_eq!(count, 1);
        count = MAX_MEMBERS;
        assert!(unsafe { copy_group_members(pointer, &mut count) }.is_err());
    }

    #[test]
    fn public_field_projection_accepts_packed_native_record_without_authentication_fields() {
        let name = std::ffi::CString::new("_aegis_network").unwrap();
        let mut members = [std::ptr::null_mut::<libc::c_char>()];
        let record = libc::group {
            gr_name: name.as_ptr().cast_mut(),
            gr_passwd: std::ptr::null_mut(),
            gr_gid: 601,
            gr_mem: members.as_mut_ptr(),
        };
        let mut storage = vec![0u8; std::mem::size_of::<libc::group>() + 1];
        let pointer = unsafe { storage.as_mut_ptr().add(1).cast::<libc::group>() };
        assert_ne!(pointer as usize % std::mem::align_of::<libc::group>(), 0);
        unsafe { std::ptr::write_unaligned(pointer, record) };
        let (native_name, gid, native_members) = unsafe { group_fields(pointer) };
        assert_eq!(
            unsafe { public_text(native_name) }.unwrap(),
            "_aegis_network"
        );
        assert_eq!(gid, 601);
        assert!(unsafe { copy_group_members(native_members, &mut 0) }
            .unwrap()
            .is_empty());
    }
}
