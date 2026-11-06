//! Wintun 0.14.1 public API, dynamically bound to the exact signed DLL for
//! the compiled Windows architecture.
//! Upstream API: https://www.wintun.net/ and its distributed wintun.h.
use sha1::Sha1;
use sha2::{Digest, Sha256};
use std::{
    ffi::c_void,
    fs::File,
    io::{self, Read},
    os::windows::ffi::OsStrExt,
    path::Path,
    ptr,
};
use windows_sys::Win32::{Foundation::*, System::LibraryLoader::*};
#[cfg(target_arch = "x86_64")]
pub const DLL_SHA256: &str = "e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce";
#[cfg(target_arch = "aarch64")]
pub const DLL_SHA256: &str = "f7ba89005544be9d85231a9e0d5f23b2d15b3311667e2dad0debd344918a3f80";
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
compile_error!("Wintun DLL identity is not pinned for this Windows architecture");
type Create = unsafe extern "system" fn(
    *const u16,
    *const u16,
    *const windows_sys::core::GUID,
) -> *mut c_void;
type Open = unsafe extern "system" fn(*const u16) -> *mut c_void;
type Close = unsafe extern "system" fn(*mut c_void);
type Luid = unsafe extern "system" fn(*mut c_void, *mut u64);
type Start = unsafe extern "system" fn(*mut c_void, u32) -> *mut c_void;
type Receive = unsafe extern "system" fn(*mut c_void, *mut u32) -> *mut u8;
type Release = unsafe extern "system" fn(*mut c_void, *const u8);
type Allocate = unsafe extern "system" fn(*mut c_void, u32) -> *mut u8;
type Send = unsafe extern "system" fn(*mut c_void, *const u8);

pub struct Wintun {
    module: HMODULE,
    _dll_lock: File,
    adapter: *mut c_void,
    session: *mut c_void,
    end: Close,
    close: Close,
    receive: Receive,
    release: Release,
    allocate: Allocate,
    send: Send,
    pub luid: u64,
}
fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}
fn wide(value: &std::ffi::OsStr) -> io::Result<Vec<u16>> {
    let mut value: Vec<u16> = value.encode_wide().collect();
    if value.contains(&0) {
        return Err(invalid("NUL in driver path"));
    }
    value.push(0);
    Ok(value)
}

fn stable_adapter_guid(name: &str) -> windows_sys::core::GUID {
    // Fixed AEGIS namespace UUID, followed by the adapter's UTF-8 name (RFC 4122 v5).
    // Keep this namespace stable across upgrades: Windows binds DNS and NLA state to
    // this adapter identity, including after an interrupted install/reboot.
    const NAMESPACE: [u8; 16] = [
        0xa2, 0x45, 0xc7, 0x57, 0x9f, 0x98, 0x4e, 0x55, 0x8d, 0xc1, 0xc0, 0x41, 0xb7, 0x81, 0x81,
        0x57,
    ];
    let mut hash = Sha1::new();
    hash.update(NAMESPACE);
    hash.update(name.as_bytes());
    let mut bytes: [u8; 20] = hash.finalize().into();
    bytes[6] = (bytes[6] & 0x0f) | 0x50;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    windows_sys::core::GUID {
        data1: u32::from_be_bytes(bytes[0..4].try_into().expect("SHA-1 prefix")),
        data2: u16::from_be_bytes(bytes[4..6].try_into().expect("SHA-1 prefix")),
        data3: u16::from_be_bytes(bytes[6..8].try_into().expect("SHA-1 prefix")),
        data4: bytes[8..16].try_into().expect("SHA-1 prefix"),
    }
}

unsafe fn open_or_create_adapter(
    name: *const u16,
    tunnel_type: *const u16,
    requested_guid: windows_sys::core::GUID,
    open: Open,
    create: Create,
) -> *mut c_void {
    // A hard reboot can leave the Wintun adapter behind because the process did
    // not get to call WintunCloseAdapter. Reuse that adapter before attempting
    // to create a new one; WintunCreateAdapter alone fails on the existing name.
    let adapter = unsafe { open(name) };
    if adapter.is_null() {
        unsafe { create(name, tunnel_type, &requested_guid) }
    } else {
        adapter
    }
}

impl Wintun {
    pub fn open(path: &Path, name: &str) -> io::Result<Self> {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ,
        };
        crate::windows_file::reject_reparse_ancestry(path)?;
        let mut lock = std::fs::OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)?;
        let meta = lock.metadata()?;
        if !meta.is_file() || meta.len() > 2 * 1024 * 1024 {
            return Err(invalid("Wintun DLL size rejected"));
        }
        let mut bytes = Vec::new();
        lock.read_to_end(&mut bytes)?;
        if format!("{:x}", Sha256::digest(&bytes)) != DLL_SHA256 {
            return Err(invalid(
                "Wintun DLL does not match the pinned signed release",
            ));
        }
        let path = path.canonicalize()?;
        let module = unsafe {
            LoadLibraryExW(
                wide(path.as_os_str())?.as_ptr(),
                ptr::null_mut(),
                LOAD_LIBRARY_SEARCH_SYSTEM32,
            )
        };
        if module.is_null() {
            return Err(io::Error::last_os_error());
        }
        let loaded = (|| unsafe {
            macro_rules! symbol {
                ($name:literal,$ty:ty) => {{
                    let function = GetProcAddress(module, concat!($name, "\0").as_ptr())
                        .ok_or_else(|| invalid("Wintun API missing"))?;
                    std::mem::transmute::<unsafe extern "system" fn() -> isize, $ty>(function)
                }};
            }
            let create = symbol!("WintunCreateAdapter", Create);
            let open = symbol!("WintunOpenAdapter", Open);
            let close = symbol!("WintunCloseAdapter", Close);
            let luid_fn = symbol!("WintunGetAdapterLUID", Luid);
            let start = symbol!("WintunStartSession", Start);
            let end = symbol!("WintunEndSession", Close);
            let receive = symbol!("WintunReceivePacket", Receive);
            let release = symbol!("WintunReleaseReceivePacket", Release);
            let allocate = symbol!("WintunAllocateSendPacket", Allocate);
            let send = symbol!("WintunSendPacket", Send);
            let adapter_name = name;
            let name = wide(std::ffi::OsStr::new(adapter_name))?;
            let tunnel_type = wide(std::ffi::OsStr::new("AEGIS"))?;
            let adapter = open_or_create_adapter(
                name.as_ptr(),
                tunnel_type.as_ptr(),
                stable_adapter_guid(adapter_name),
                open,
                create,
            );
            if adapter.is_null() {
                return Err(io::Error::last_os_error());
            }
            let session = start(adapter, 0x400000);
            if session.is_null() {
                let error = io::Error::last_os_error();
                close(adapter);
                return Err(error);
            }
            let mut luid = 0;
            luid_fn(adapter, &mut luid);
            Ok(Self {
                module,
                _dll_lock: lock,
                adapter,
                session,
                end,
                close,
                receive,
                release,
                allocate,
                send,
                luid,
            })
        })();
        if loaded.is_err() {
            unsafe {
                FreeLibrary(module);
            }
        }
        loaded
    }
    pub fn receive(&mut self) -> io::Result<Option<Vec<u8>>> {
        let mut size = 0;
        let packet = unsafe { (self.receive)(self.session, &mut size) };
        if packet.is_null() {
            let error = io::Error::last_os_error();
            return if error.raw_os_error() == Some(ERROR_NO_MORE_ITEMS as i32) {
                Ok(None)
            } else {
                Err(error)
            };
        }
        let result = if (20..=65535).contains(&size) {
            Ok(Some(
                unsafe { std::slice::from_raw_parts(packet, size as usize) }.to_vec(),
            ))
        } else {
            Err(invalid("Wintun packet size rejected"))
        };
        unsafe { (self.release)(self.session, packet) };
        result
    }
    pub fn send(&mut self, packet: &[u8]) -> io::Result<()> {
        if !(20..=65535).contains(&packet.len()) {
            return Err(invalid("invalid IP packet size"));
        }
        let output = unsafe { (self.allocate)(self.session, packet.len() as u32) };
        if output.is_null() {
            return Err(io::Error::last_os_error());
        }
        unsafe {
            ptr::copy_nonoverlapping(packet.as_ptr(), output, packet.len());
            (self.send)(self.session, output);
        }
        Ok(())
    }
}

impl Drop for Wintun {
    fn drop(&mut self) {
        unsafe {
            (self.end)(self.session);
            (self.close)(self.adapter);
            FreeLibrary(self.module);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Mutex,
    };

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static OPEN_CALLS: AtomicUsize = AtomicUsize::new(0);
    static CREATE_CALLS: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "system" fn open_existing(_name: *const u16) -> *mut c_void {
        OPEN_CALLS.fetch_add(1, Ordering::Relaxed);
        std::ptr::NonNull::<u8>::dangling().as_ptr().cast()
    }

    unsafe extern "system" fn open_missing(_name: *const u16) -> *mut c_void {
        OPEN_CALLS.fetch_add(1, Ordering::Relaxed);
        ptr::null_mut()
    }

    unsafe extern "system" fn create_adapter(
        _name: *const u16,
        _tunnel_type: *const u16,
        _requested_guid: *const windows_sys::core::GUID,
    ) -> *mut c_void {
        CREATE_CALLS.fetch_add(1, Ordering::Relaxed);
        std::ptr::NonNull::<u8>::dangling().as_ptr().cast()
    }

    #[test]
    fn existing_adapter_is_reopened_after_interrupted_shutdown() {
        let _lock = TEST_LOCK.lock().unwrap();
        OPEN_CALLS.store(0, Ordering::Relaxed);
        CREATE_CALLS.store(0, Ordering::Relaxed);
        let adapter = unsafe {
            open_or_create_adapter(
                ptr::null(),
                ptr::null(),
                stable_adapter_guid("AEGIS"),
                open_existing,
                create_adapter,
            )
        };
        assert!(!adapter.is_null());
        assert_eq!(OPEN_CALLS.load(Ordering::Relaxed), 1);
        assert_eq!(CREATE_CALLS.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn missing_adapter_is_created() {
        let _lock = TEST_LOCK.lock().unwrap();
        OPEN_CALLS.store(0, Ordering::Relaxed);
        CREATE_CALLS.store(0, Ordering::Relaxed);
        let adapter = unsafe {
            open_or_create_adapter(
                ptr::null(),
                ptr::null(),
                stable_adapter_guid("AEGIS"),
                open_missing,
                create_adapter,
            )
        };
        assert!(!adapter.is_null());
        assert_eq!(OPEN_CALLS.load(Ordering::Relaxed), 1);
        assert_eq!(CREATE_CALLS.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn stable_guid_is_rfc4122_v5_and_name_scoped() {
        let guid = stable_adapter_guid("AEGIS");
        assert_eq!(guid.data1, 0x686fa4ce);
        assert_eq!(guid.data2, 0xd968);
        assert_eq!(guid.data3, 0x5961);
        assert_eq!(guid.data4, [0x92, 0x6a, 0xaa, 0x15, 0x90, 0x1e, 0xe2, 0xd0]);
        let repeat = stable_adapter_guid("AEGIS");
        assert_eq!(
            (guid.data1, guid.data2, guid.data3, guid.data4),
            (repeat.data1, repeat.data2, repeat.data3, repeat.data4)
        );
        assert_ne!(guid.data1, stable_adapter_guid("AEGIS-other").data1);
    }
}
