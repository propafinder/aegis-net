use super::*;
use std::{fs::File, io::Read, time::Duration};

fn pair() -> (UnixStream, UnixStream) {
    let pair = UnixStream::pair().unwrap();
    for stream in [&pair.0, &pair.1] {
        stream
            .set_read_timeout(Some(Duration::from_millis(100)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_millis(100)))
            .unwrap();
    }
    pair
}

fn identity() -> PeerIdentity {
    PeerIdentity {
        uid: unsafe { libc::geteuid() },
        pid: unsafe { libc::getpid() },
    }
}

#[test]
fn actual_socketpair_kernel_identity_matches_the_owned_process() {
    let (left, right) = pair();
    assert_eq!(peer_identity(&left).unwrap(), identity());
    assert_eq!(peer_identity(&right).unwrap(), identity());
}

#[test]
fn actual_uid_or_pid_mismatch_prevents_descriptor_transfer() {
    let current = identity();
    for expected in [
        PeerIdentity {
            uid: current.uid + 1,
            ..current
        },
        PeerIdentity {
            pid: current.pid + 1,
            ..current
        },
    ] {
        let (sender, mut receiver) = pair();
        let fd = File::open("/dev/null").unwrap();
        let error = send_fd_to_peer(&sender, fd.as_raw_fd(), b"utun7", expected).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        let mut data = [0; 1];
        let error = receiver.read(&mut data).unwrap_err();
        assert!(matches!(
            error.kind(),
            io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
        ));
    }
}

#[test]
fn actual_expected_peer_transfer_preserves_immediate_owned_custody() {
    let (sender, receiver) = pair();
    let fd = File::open("/dev/null").unwrap();
    send_fd_to_peer(&sender, fd.as_raw_fd(), b"utun7", identity()).unwrap();
    let (received, name) = recv_fd_from_peer(&receiver, identity().uid).unwrap();
    assert_eq!(name, "utun7");
    assert!(unsafe { libc::fcntl(received.as_raw_fd(), libc::F_GETFD) } >= 0);
}

#[test]
fn actual_root_uid_admission_refuses_the_non_root_socketpair() {
    assert_ne!(identity().uid, 0, "fixture must not run as root");
    let (sender, receiver) = pair();
    let fd = File::open("/dev/null").unwrap();
    send_fd(&sender, fd.as_raw_fd(), b"utun7").unwrap();
    let error = recv_fd_from_peer(&receiver, 0).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
}

#[test]
fn actual_refused_transfer_closes_all_installed_descriptors() {
    use super::tests::raw_send;
    for count in [1, 2, 128] {
        let (sender, receiver) = pair();
        let (writer, mut reader) = pair();
        raw_send(
            &sender,
            &vec![writer.as_raw_fd(); count],
            b"malformed metadata",
        );
        drop(writer);
        assert!(recv_fd(&receiver).is_err());
        let mut byte = [0; 1];
        assert_eq!(
            reader
                .read(&mut byte)
                .unwrap_or_else(|error| panic!("descriptor count={count}: {error}")),
            0,
            "descriptor count={count}"
        );
    }
}

#[test]
fn actual_short_metadata_frame_refuses_and_closes_the_received_descriptor() {
    use super::tests::raw_send;
    let (sender, receiver) = pair();
    let (writer, mut reader) = pair();
    raw_send(&sender, &[writer.as_raw_fd()], b"AEFD\x01\x05u");
    drop(writer);
    assert!(recv_fd(&receiver).is_err());
    let mut byte = [0; 1];
    assert_eq!(reader.read(&mut byte).unwrap(), 0);
}

#[test]
fn actual_sender_peer_disconnect_is_an_error_without_a_process_signal() {
    let (sender, receiver) = pair();
    drop(receiver);
    let fd = File::open("/dev/null").unwrap();
    assert!(send_fd(&sender, fd.as_raw_fd(), b"utun7").is_err());
}

#[test]
fn capacity_selector_bounds_every_installable_fd_header_and_refuses_unsupported_limits() {
    let per_fd = unsafe { libc::CMSG_SPACE(mem::size_of::<RawFd>() as u32) } as usize;
    let framing = unsafe { libc::CMSG_SPACE(0) } as usize;
    for limit in [1, 64, 128] {
        let capacity = receive_capacity_for_limit(limit).unwrap();
        assert_eq!(capacity, limit as usize * per_fd + framing);
        assert!(
            capacity.div_ceil(mem::size_of::<libc::cmsghdr>()) * mem::size_of::<libc::cmsghdr>()
                <= MAX_CONTROL_BYTES
        );
    }
    for limit in [
        0,
        libc::RLIM_INFINITY,
        libc::rlim_t::MAX - 1,
        MAX_CONTROL_BYTES as libc::rlim_t,
    ] {
        assert!(receive_capacity_for_limit(limit).is_err());
    }
}

#[test]
fn unsupported_capacity_refuses_before_receive_and_keeps_the_owned_message_pending() {
    let (sender, receiver) = pair();
    let fd = File::open("/dev/null").unwrap();
    send_fd(&sender, fd.as_raw_fd(), b"utun7").unwrap();
    assert!(recv_fd_for_limit(&receiver, libc::RLIM_INFINITY).is_err());
    // The same real channel still contains its one valid transfer. The failed
    // capacity decision did not enter recvmsg or install an unseen descriptor.
    let (received, name) = recv_fd(&receiver).unwrap();
    assert_eq!(name, "utun7");
    assert!(unsafe { libc::fcntl(received.as_raw_fd(), libc::F_GETFD) } >= 0);
}
