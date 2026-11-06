//! Prepare only the local SOCKS credential, never a global Keychain ACL.
//! Password arrives on stdin; no secret arguments, output, or shell invocation.
use std::{
    ffi::{c_void, CString},
    io::{self, Read},
    ptr,
};
type Ref = *const c_void;
#[link(name = "CoreFoundation", kind = "framework")]
unsafe extern "C" {
    fn CFRelease(value: Ref);
    fn CFStringCreateWithCString(a: Ref, s: *const i8, encoding: u32) -> Ref;
    fn CFArrayCreate(a: Ref, values: *const Ref, count: isize, callbacks: Ref) -> Ref;
    static kCFTypeArrayCallBacks: [usize; 5];
}
#[link(name = "Security", kind = "framework")]
unsafe extern "C" {
    fn SecKeychainCopyDefault(keychain: *mut Ref) -> i32;
    fn SecTrustedApplicationCreateFromPath(path: *const i8, app: *mut Ref) -> i32;
    fn SecAccessCreate(description: Ref, apps: Ref, access: *mut Ref) -> i32;
    fn SecKeychainFindInternetPassword(
        keychains: Ref,
        server_len: u32,
        server: *const u8,
        domain_len: u32,
        domain: *const u8,
        account_len: u32,
        account: *const u8,
        path_len: u32,
        path: *const u8,
        port: u16,
        protocol: u32,
        auth: u32,
        password_len: *mut u32,
        password: *mut *mut c_void,
        item: *mut Ref,
    ) -> i32;
    fn SecKeychainAddInternetPassword(
        keychain: Ref,
        server_len: u32,
        server: *const u8,
        domain_len: u32,
        domain: *const u8,
        account_len: u32,
        account: *const u8,
        path_len: u32,
        path: *const u8,
        port: u16,
        protocol: u32,
        auth: u32,
        password_len: u32,
        password: *const u8,
        item: *mut Ref,
    ) -> i32;
    fn SecKeychainItemModifyAttributesAndData(
        item: Ref,
        attrs: Ref,
        len: u32,
        data: *const u8,
    ) -> i32;
    fn SecKeychainItemSetAccess(item: Ref, access: Ref) -> i32;
}
struct Owned(Ref);
impl Drop for Owned {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { CFRelease(self.0) }
        }
    }
}
struct Secret {
    bytes: Vec<u8>,
    used: usize,
    #[cfg(test)]
    observe_wipe: Option<Box<dyn FnOnce(&[u8])>>,
}
impl Secret {
    fn new() -> Self {
        // Read only into this fixed allocation: no reserve, resize or EOF probe
        // may move a partial credential to an allocation outside this owner.
        Self {
            bytes: vec![0; 257],
            used: 0,
            #[cfg(test)]
            observe_wipe: None,
        }
    }
    fn read(mut self, mut input: impl Read) -> Result<Self, String> {
        while self.used < self.bytes.len() {
            match input.read(&mut self.bytes[self.used..]) {
                Ok(0) => break,
                Ok(count) => self.used += count,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(_) => return Err("cannot read proxy credential".into()),
            }
        }
        if self.as_bytes().last() == Some(&b'\n') {
            self.used -= 1;
        }
        if self.used == 0 || self.used > 255 || !self.as_bytes().iter().all(u8::is_ascii_hexdigit) {
            return Err("invalid proxy credential".into());
        }
        Ok(self)
    }
    fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.used]
    }
}
impl Drop for Secret {
    fn drop(&mut self) {
        for byte in &mut self.bytes {
            unsafe { ptr::write_volatile(byte, 0) }
        }
        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
        #[cfg(test)]
        if let Some(observe) = self.observe_wipe.take() {
            observe(&self.bytes);
        }
    }
}
fn checked(status: i32) -> Result<(), String> {
    if status == 0 {
        Ok(())
    } else {
        Err(format!(
            "Keychain operation failed (OSStatus {status}); proxy setup incomplete"
        ))
    }
}
const APPS: &[&str] = &[
    "/usr/sbin/networksetup",
    "/usr/libexec/nsurlsessiond",
    "/System/Library/PrivateFrameworks/CoreParsec.framework/parsecd",
    "/System/Library/Frameworks/WebKit.framework/Versions/A/XPCServices/com.apple.WebKit.Networking.xpc/Contents/MacOS/com.apple.WebKit.Networking",
];
fn run() -> Result<(), String> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.len() != 2 {
        return Err("usage: aegis-proxy-keychain <port> <account> (password on stdin)".into());
    }
    let port: u16 = args[0].parse().map_err(|_| "invalid port")?;
    let account = args[1].as_bytes();
    if port == 0
        || account.is_empty()
        || account.len() > 255
        || !account
            .iter()
            .all(|c| c.is_ascii_alphanumeric() || b"-_.".contains(c))
    {
        return Err("invalid local SOCKS identity".into());
    }
    // Resolve the system's current WebKit/Cryptex executable each installation.
    // No caller-controlled executable paths and no allow-all-applications option.
    let mut apps = Vec::new();
    for path in APPS {
        let path =
            std::fs::canonicalize(path).map_err(|_| "required system proxy consumer missing")?;
        let path =
            CString::new(path.as_os_str().as_encoded_bytes()).map_err(|_| "invalid system path")?;
        let mut app = ptr::null();
        checked(unsafe { SecTrustedApplicationCreateFromPath(path.as_ptr(), &mut app) })?;
        apps.push(Owned(app));
    }
    let refs: Vec<_> = apps.iter().map(|v| v.0).collect();
    let array = Owned(unsafe {
        CFArrayCreate(
            ptr::null(),
            refs.as_ptr(),
            refs.len() as isize,
            ptr::addr_of!(kCFTypeArrayCallBacks).cast(),
        )
    });
    let desc = CString::new("Aegis local SOCKS proxy").unwrap();
    let desc = Owned(unsafe { CFStringCreateWithCString(ptr::null(), desc.as_ptr(), 0x08000100) });
    if array.0.is_null() || desc.0.is_null() {
        return Err("cannot create restricted proxy access".into());
    }
    let mut access = ptr::null();
    checked(unsafe { SecAccessCreate(desc.0, array.0, &mut access) })?;
    let access = Owned(access);
    let secret = Secret::new().read(io::stdin())?;
    let mut keychain = ptr::null();
    checked(unsafe { SecKeychainCopyDefault(&mut keychain) })?;
    let keychain = Owned(keychain);
    let server = b"127.0.0.1";
    let mut item = ptr::null();
    let protocol = u32::from_be_bytes(*b"sox ");
    let auth = u32::from_le_bytes(*b"dflt");
    let status = unsafe {
        SecKeychainFindInternetPassword(
            keychain.0,
            9,
            server.as_ptr(),
            0,
            ptr::null(),
            account.len() as u32,
            account.as_ptr(),
            0,
            ptr::null(),
            port,
            protocol,
            auth,
            ptr::null_mut(),
            ptr::null_mut(),
            &mut item,
        )
    };
    let status = if status == -25300 {
        unsafe {
            SecKeychainAddInternetPassword(
                keychain.0,
                9,
                server.as_ptr(),
                0,
                ptr::null(),
                account.len() as u32,
                account.as_ptr(),
                0,
                ptr::null(),
                port,
                protocol,
                auth,
                secret.as_bytes().len() as u32,
                secret.as_bytes().as_ptr(),
                &mut item,
            )
        }
    } else if status == 0 {
        unsafe {
            SecKeychainItemModifyAttributesAndData(
                item,
                ptr::null(),
                secret.as_bytes().len() as u32,
                secret.as_bytes().as_ptr(),
            )
        }
    } else {
        status
    };
    // The RAII owner also wipes partial reads and every early error return.
    // Clear it before access preparation can request further authorization.
    drop(secret);
    let item = Owned(item);
    checked(status)?;
    checked(unsafe { SecKeychainItemSetAccess(item.0, access.0) })?;
    println!("Local proxy credential prepared for four named system consumers; system proxy routing unchanged.");
    Ok(())
}
fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn partial_stdin_error_wipes_the_bytes_already_read() {
        struct FailingInput(bool);
        impl Read for FailingInput {
            fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
                if self.0 {
                    return Err(io::Error::other("synthetic stdin failure"));
                }
                self.0 = true;
                buffer[..4].copy_from_slice(b"abcd");
                Ok(4)
            }
        }
        let observed = std::sync::Arc::new(std::sync::Mutex::new(None));
        let observer = observed.clone();
        let mut secret = Secret::new();
        secret.observe_wipe = Some(Box::new(move |bytes| {
            *observer.lock().unwrap() = Some(bytes.to_vec());
        }));
        assert!(secret.read(FailingInput(false)).is_err());
        assert_eq!(*observed.lock().unwrap(), Some(vec![0; 257]));
    }
    #[test]
    fn credential_read_is_bounded_and_accepts_only_hex() {
        let accepted = Secret::new().read(&b"abcd\n"[..]).unwrap();
        assert_eq!(accepted.as_bytes(), b"abcd");
        for invalid in [b"".as_slice(), b"not-hex", &[b'a'; 256]] {
            assert!(Secret::new().read(invalid).is_err());
        }
    }
    #[test]
    fn full_input_stops_at_the_fixed_buffer_without_an_eof_probe() {
        struct FullInput(usize);
        impl Read for FullInput {
            fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
                assert_eq!(self.0, 0, "read exceeded the fixed input buffer");
                self.0 += 1;
                assert_eq!(buffer.len(), 257);
                buffer.fill(b'a');
                Ok(buffer.len())
            }
        }
        let mut input = FullInput(0);
        assert!(Secret::new().read(&mut input).is_err());
        assert_eq!(input.0, 1);
    }
    #[test]
    fn native_restricted_access_accepts_current_system_consumers() {
        let mut apps = Vec::new();
        for path in APPS {
            let path = std::fs::canonicalize(path).expect("system consumer exists");
            let path = CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
            let mut app = ptr::null();
            checked(unsafe { SecTrustedApplicationCreateFromPath(path.as_ptr(), &mut app) })
                .unwrap();
            assert!(!app.is_null());
            apps.push(Owned(app));
        }
        let refs: Vec<_> = apps.iter().map(|v| v.0).collect();
        let array = Owned(unsafe {
            CFArrayCreate(
                ptr::null(),
                refs.as_ptr(),
                4,
                ptr::addr_of!(kCFTypeArrayCallBacks).cast(),
            )
        });
        let text = CString::new("Aegis proxy ACL regression").unwrap();
        let desc =
            Owned(unsafe { CFStringCreateWithCString(ptr::null(), text.as_ptr(), 0x08000100) });
        let mut access = ptr::null();
        checked(unsafe { SecAccessCreate(desc.0, array.0, &mut access) }).unwrap();
        let access = Owned(access);
        assert!(!access.0.is_null());
        // No credential creation or modification in this regression.
    }
}
