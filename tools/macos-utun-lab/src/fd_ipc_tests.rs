use super::*;
use std::{
    fs::File,
    os::fd::{FromRawFd, OwnedFd},
    time::Duration,
};

// Keep the same regression source across the original RawFd API and the
// repaired OwnedFd API. Every successful baseline receipt is immediately owned
// by the test so failed assertions do not leave that descriptor open.
trait ReceivedFd {
    fn into_owned(self) -> OwnedFd;
}

impl ReceivedFd for RawFd {
    fn into_owned(self) -> OwnedFd {
        // SAFETY: recv_fd returned the newly installed SCM_RIGHTS descriptor.
        unsafe { OwnedFd::from_raw_fd(self) }
    }
}

impl ReceivedFd for OwnedFd {
    fn into_owned(self) -> OwnedFd {
        self
    }
}

fn pair() -> (UnixStream, UnixStream) {
    let pair = UnixStream::pair().unwrap();
    for socket in [&pair.0, &pair.1] {
        socket
            .set_read_timeout(Some(Duration::from_millis(250)))
            .unwrap();
        socket
            .set_write_timeout(Some(Duration::from_millis(250)))
            .unwrap();
    }
    pair
}

fn descriptor() -> File {
    File::open("/dev/null").unwrap()
}

pub(super) fn raw_send(stream: &UnixStream, fds: &[RawFd], data: &[u8]) {
    // cmsghdr elements provide native alignment and enough bounded storage for
    // the deliberately malformed/truncated transfer fixtures.
    let mut control: [libc::cmsghdr; 256] = unsafe { mem::zeroed() };
    let mut iov = libc::iovec {
        iov_base: data.as_ptr() as *mut libc::c_void,
        iov_len: data.len(),
    };
    let mut message: libc::msghdr = unsafe { mem::zeroed() };
    message.msg_iov = &mut iov;
    message.msg_iovlen = 1;
    if !fds.is_empty() {
        let length = mem::size_of_val(fds) as u32;
        message.msg_control = control.as_mut_ptr().cast();
        message.msg_controllen = unsafe { libc::CMSG_SPACE(length) } as _;
        // SAFETY: the aligned bounded control region fits the complete header
        // and at most128 borrowed descriptors; sendmsg duplicates them.
        unsafe {
            let header = libc::CMSG_FIRSTHDR(&message);
            (*header).cmsg_level = libc::SOL_SOCKET;
            (*header).cmsg_type = libc::SCM_RIGHTS;
            (*header).cmsg_len = libc::CMSG_LEN(length) as _;
            std::ptr::copy_nonoverlapping(fds.as_ptr(), libc::CMSG_DATA(header).cast(), fds.len());
        }
    }
    // SAFETY: the iovec and optional control remain live for this synchronous
    // call; both socketpair ends and all original descriptors are owned here.
    let written = unsafe { libc::sendmsg(stream.as_raw_fd(), &message, libc::MSG_NOSIGNAL) };
    assert_eq!(written, data.len() as isize);
}

#[test]
fn actual_fd_transfer_preserves_the_single_descriptor_and_name() {
    let (sender, receiver) = pair();
    let original = descriptor();
    send_fd(&sender, original.as_raw_fd(), b"utun7").unwrap();
    let (received, name) = recv_fd(&receiver).unwrap();
    let received = received.into_owned();
    assert_eq!(name, "utun7");
    assert_ne!(received.as_raw_fd(), original.as_raw_fd());
    assert!(unsafe { libc::fcntl(received.as_raw_fd(), libc::F_GETFD) } >= 0);
    drop(received);
    assert!(unsafe { libc::fcntl(original.as_raw_fd(), libc::F_GETFD) } >= 0);
}

#[test]
fn actual_received_descriptor_is_close_on_exec() {
    let (sender, receiver) = pair();
    let original = descriptor();
    send_fd(&sender, original.as_raw_fd(), b"utun7").unwrap();
    let (received, _) = recv_fd(&receiver).unwrap();
    let received = received.into_owned();
    let flags = unsafe { libc::fcntl(received.as_raw_fd(), libc::F_GETFD) };
    assert!(flags >= 0);
    assert_ne!(flags & libc::FD_CLOEXEC, 0);
}

#[test]
fn actual_multiple_or_truncated_rights_are_refused() {
    for count in [2, 128] {
        let (sender, receiver) = pair();
        let original = descriptor();
        raw_send(&sender, &vec![original.as_raw_fd(); count], b"utun7");
        let result = recv_fd(&receiver).map(|(fd, name)| (fd.into_owned(), name));
        assert!(result.is_err(), "descriptor count={count}");
    }
}

#[test]
fn actual_invalid_utf8_and_oversized_metadata_are_refused() {
    for data in [vec![0xff, b'u'], vec![b'u'; 80]] {
        let (sender, receiver) = pair();
        let original = descriptor();
        raw_send(&sender, &[original.as_raw_fd()], &data);
        let result = recv_fd(&receiver).map(|(fd, name)| (fd.into_owned(), name));
        assert!(result.is_err());
    }
}

#[test]
fn actual_missing_rights_are_refused() {
    let (sender, receiver) = pair();
    raw_send(&sender, &[], b"utun7");
    assert!(recv_fd(&receiver).is_err());
}

#[test]
fn actual_sender_refuses_invalid_interface_metadata_before_transfer() {
    let (sender, _receiver) = pair();
    let original = descriptor();
    assert!(send_fd(&sender, original.as_raw_fd(), b"not-utun").is_err());
}
