use tokio::net::TcpStream;

#[cfg(unix)]
use std::os::fd::{AsRawFd, RawFd};

#[cfg(unix)]
pub(super) fn local_session_aborted_fd(fd: RawFd) -> bool {
    // The accepted ingress socket is already non-blocking under Tokio, so a
    // peeking recv lets us cheaply distinguish:
    // - `0` / reset-like errors: the local client is already gone
    // - `WouldBlock`: the client is still open, just idle
    // - `>0`: buffered client payload exists
    let mut byte = 0u8;
    let n = unsafe {
        libc::recv(
            fd,
            (&mut byte as *mut u8).cast::<libc::c_void>(),
            1,
            libc::MSG_PEEK | libc::MSG_DONTWAIT,
        )
    };
    if n > 0 {
        return false;
    }
    if n == 0 {
        return true;
    }
    let err = std::io::Error::last_os_error();
    !matches!(
        err.kind(),
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
    )
}

pub(super) fn local_session_aborted(local: &TcpStream) -> bool {
    #[cfg(unix)]
    {
        local_session_aborted_fd(local.as_raw_fd())
    }

    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawSocket;
        use windows_sys::Win32::Networking::WinSock::{
            recv, WSAGetLastError, MSG_PEEK, WSAEINTR, WSAEWOULDBLOCK,
        };
        let mut byte = 0u8;
        // Tokio's socket is nonblocking; peek without consuming application data.
        let count = unsafe { recv(local.as_raw_socket() as usize, &mut byte, 1, MSG_PEEK) };
        count == 0
            || (count < 0 && !matches!(unsafe { WSAGetLastError() }, WSAEWOULDBLOCK | WSAEINTR))
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = local;
        false
    }
}

pub(super) fn local_session_pre_open_aborted(
    local: &TcpStream,
    initial_payload: Option<&[u8]>,
) -> bool {
    initial_payload.is_none() && local_session_aborted(local)
}
