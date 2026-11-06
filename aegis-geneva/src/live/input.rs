//! Finite local strategy loading: never wait on FIFO/device or follow a symlink.
use std::{
    fs::OpenOptions,
    io::{self, Read},
    os::unix::fs::OpenOptionsExt,
    path::Path,
};
pub fn load(path: &Path) -> io::Result<String> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)?;
    if !file.metadata()?.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "strategy must be a regular file",
        ));
    }
    let mut bytes = Vec::new();
    file.take(65537).read_to_end(&mut bytes)?;
    if bytes.len() > 65536 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "strategy exceeds 64 KiB",
        ));
    }
    String::from_utf8(bytes)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "strategy is not UTF-8"))
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn regular_oversize_symlink_and_fifo_are_bounded_without_packet_sockets() {
        use std::{
            ffi::CString,
            os::unix::{ffi::OsStrExt, fs::symlink},
            sync::atomic::{AtomicU64, Ordering},
        };
        static SERIAL: AtomicU64 = AtomicU64::new(0);
        let root = std::env::temp_dir().join(format!(
            "aegis-geneva-input-{}-{}",
            std::process::id(),
            SERIAL.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&root).unwrap();
        let regular = root.join("regular");
        std::fs::write(&regular, b"[IP:ttl:64]--|").unwrap();
        assert_eq!(load(&regular).unwrap(), "[IP:ttl:64]--|");
        let large = root.join("large");
        std::fs::write(&large, vec![b'A'; 65537]).unwrap();
        assert!(load(&large).is_err());
        let alias = root.join("alias");
        symlink(&regular, &alias).unwrap();
        assert!(load(&alias).is_err());
        let fifo = root.join("fifo");
        let name = CString::new(fifo.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
        assert!(load(&fifo).is_err());
        for path in [regular, large, alias, fifo] {
            std::fs::remove_file(path).unwrap();
        }
        std::fs::remove_dir(root).unwrap();
    }
}
