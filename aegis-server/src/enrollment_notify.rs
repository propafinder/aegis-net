//! Readiness acknowledges validated authority state and a bound listener.
//! Certificate issuance does not acknowledge distribution to relay processes.

use std::io;

pub(crate) fn notify() -> io::Result<()> {
    #[cfg(target_os = "linux")]
    return notify_at(std::env::var_os("NOTIFY_SOCKET").as_deref());
    #[cfg(not(target_os = "linux"))]
    Ok(())
}

#[cfg(target_os = "linux")]
fn notify_at(address: Option<&std::ffi::OsStr>) -> io::Result<()> {
    use std::os::linux::net::SocketAddrExt;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::net::{SocketAddr, UnixDatagram};
    use std::path::Path;
    use std::time::Duration;

    let Some(address) = address else {
        return Ok(());
    };
    let raw = address.as_bytes();
    let invalid = || io::Error::new(io::ErrorKind::InvalidInput, "invalid service notify socket");
    if raw.contains(&0) {
        return Err(invalid());
    }
    let target = match raw.first() {
        Some(b'@') if raw.len() > 1 => SocketAddr::from_abstract_name(&raw[1..])?,
        Some(b'/') => SocketAddr::from_pathname(Path::new(address))?,
        _ => return Err(invalid()),
    };
    let socket = UnixDatagram::unbound()?;
    socket.set_write_timeout(Some(Duration::from_secs(1)))?;
    socket.connect_addr(&target)?;
    let message = b"READY=1\nSTATUS=Authority listener ready";
    if socket.send(message)? != message.len() {
        return Err(io::Error::new(
            io::ErrorKind::WriteZero,
            "short readiness datagram",
        ));
    }
    Ok(())
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use std::ffi::OsStr;
    use std::os::linux::net::SocketAddrExt;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::net::{SocketAddr, UnixDatagram};
    use std::time::Duration;

    fn assert_ready(receiver: &UnixDatagram) {
        receiver
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let mut data = [0; 128];
        let n = receiver.recv(&mut data).unwrap();
        assert_eq!(&data[..n], b"READY=1\nSTATUS=Authority listener ready");
    }

    #[test]
    fn filesystem_socket_receives_ready() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("notify");
        let receiver = UnixDatagram::bind(&path).unwrap();
        notify_at(Some(path.as_os_str())).unwrap();
        assert_ready(&receiver);
    }

    #[test]
    fn abstract_socket_receives_ready() {
        let dir = tempfile::tempdir().unwrap();
        let name = dir.path().as_os_str().as_bytes();
        let receiver =
            UnixDatagram::bind_addr(&SocketAddr::from_abstract_name(name).unwrap()).unwrap();
        let mut notify_name = vec![b'@'];
        notify_name.extend_from_slice(name);
        notify_at(Some(OsStr::from_bytes(&notify_name))).unwrap();
        assert_ready(&receiver);
    }

    #[test]
    fn absent_socket_is_optional_but_bad_config_is_not() {
        notify_at(None).unwrap();
        for raw in [b"".as_slice(), b"@", b"relative/path", b"/bad\0path"] {
            assert_eq!(
                notify_at(Some(OsStr::from_bytes(raw))).unwrap_err().kind(),
                io::ErrorKind::InvalidInput
            );
        }
        let dir = tempfile::tempdir().unwrap();
        assert!(notify_at(Some(dir.path().join("missing").as_os_str())).is_err());
    }
}
