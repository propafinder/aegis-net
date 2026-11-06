#[cfg(any(target_os = "linux", test))]
use std::io;

/// Linux-only opt-in mark for sockets that must bypass AEGIS's own transparent
/// OUTPUT capture. The installer sets this only for the hybrid Geneva profile.
pub const DIRECT_SOCKET_MARK_ENV: &str = "AEGIS_DIRECT_SOCKET_MARK";

#[cfg(any(target_os = "linux", test))]
fn parse_direct_socket_mark(value: Option<&str>) -> io::Result<Option<u32>> {
    let Some(value) = value.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(None);
    };
    let mark = value.parse::<u32>().map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{DIRECT_SOCKET_MARK_ENV} must be a non-zero u32"),
        )
    })?;
    if mark == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{DIRECT_SOCKET_MARK_ENV} must be a non-zero u32"),
        ));
    }
    Ok(Some(mark))
}

/// Apply the configured direct-egress SO_MARK to a Linux socket.
///
/// Missing configuration is an intentional no-op for ordinary Direct mode.
/// When the hybrid installer configures a mark, failure is terminal: continuing
/// would feed the client's direct connection back into its own wide listener.
#[cfg(target_os = "linux")]
pub fn apply_configured_direct_socket_mark(fd: std::os::fd::RawFd) -> io::Result<()> {
    use std::mem;

    let Some(mark) =
        parse_direct_socket_mark(std::env::var(DIRECT_SOCKET_MARK_ENV).ok().as_deref())?
    else {
        return Ok(());
    };
    let rc = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_MARK,
            (&mark as *const u32).cast(),
            mem::size_of_val(&mark) as libc::socklen_t,
        )
    };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn direct_socket_mark_is_optional_and_strict() {
        assert_eq!(parse_direct_socket_mark(None).unwrap(), None);
        assert_eq!(parse_direct_socket_mark(Some(" ")).unwrap(), None);
        assert_eq!(
            parse_direct_socket_mark(Some("44641")).unwrap(),
            Some(44641)
        );
        assert!(parse_direct_socket_mark(Some("0")).is_err());
        assert!(parse_direct_socket_mark(Some("-1")).is_err());
        assert!(parse_direct_socket_mark(Some("not-a-mark")).is_err());
    }
}
