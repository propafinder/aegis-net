use super::*;
use std::time::{Duration, Instant};
fn packet(version: u8) -> Vec<u8> {
    let mut p = vec![0; if version == 4 { 20 } else { 40 }];
    p[0] = version << 4;
    p
}
fn encoded(direction: u8, p: &[u8]) -> Vec<u8> {
    let mut frame = vec![b'A', b'P', 1, direction];
    frame.extend_from_slice(&(p.len() as u32).to_be_bytes());
    frame.extend_from_slice(p);
    frame
}
fn raw_pair(limits: Limits) -> (PacketPort, CancelHandle, UnixStream) {
    let (a, b) = UnixStream::pair().unwrap();
    let (port, cancel) = PacketPort::new(a, Role::Worker, limits).unwrap();
    b.set_read_timeout(Some(Duration::from_millis(200)))
        .unwrap();
    (port, cancel, b)
}
fn read_until(port: &mut PacketPort) -> io::Result<Vec<u8>> {
    let end = Instant::now() + Duration::from_secs(1);
    loop {
        if let Some(p) = port.receive()? {
            return Ok(p);
        }
        assert!(Instant::now() < end, "owned IPC progress deadline");
        std::thread::yield_now();
    }
}
#[test]
fn worker_ipc_actual_dual_stack_roundtrip_and_direction() {
    let (a, b) = UnixStream::pair().unwrap();
    let (mut parent, _) = PacketPort::new(a, Role::Parent, Limits::default()).unwrap();
    let (mut worker, _) = PacketPort::new(b, Role::Worker, Limits::default()).unwrap();
    for v in [4, 6] {
        let p = packet(v);
        parent.send(&p).unwrap();
        assert_eq!(read_until(&mut worker).unwrap(), p);
        worker.send(&p).unwrap();
        assert_eq!(read_until(&mut parent).unwrap(), p);
    }
}
#[test]
fn worker_ipc_partial_header_payload_and_coalesced_packets_never_deliver_partial_data() {
    let (mut port, _, mut raw) = raw_pair(Limits::default());
    let frame = encoded(1, &packet(4));
    raw.write_all(&frame[..3]).unwrap();
    assert!(port.receive().unwrap().is_none());
    raw.write_all(&frame[3..12]).unwrap();
    assert!(port.receive().unwrap().is_none());
    let mut rest = frame[12..].to_vec();
    rest.extend_from_slice(&encoded(1, &packet(6)));
    raw.write_all(&rest).unwrap();
    assert_eq!(read_until(&mut port).unwrap(), packet(4));
    assert_eq!(read_until(&mut port).unwrap(), packet(6));
    assert!(port.receive().unwrap().is_none());
}
#[test]
fn worker_ipc_eof_empty_partial_header_and_partial_payload_are_terminal() {
    for cut in [0, 3, 12] {
        let (mut port, _, mut raw) = raw_pair(Limits::default());
        let frame = encoded(1, &packet(4));
        raw.write_all(&frame[..cut]).unwrap();
        drop(raw);
        assert_eq!(
            port.receive().unwrap_err().kind(),
            io::ErrorKind::UnexpectedEof
        );
        assert_eq!(
            port.receive().unwrap_err().kind(),
            io::ErrorKind::UnexpectedEof
        );
    }
}
#[test]
fn worker_ipc_version_magic_direction_and_oversize_rejected_before_payload_allocation() {
    for defect in 0..6 {
        let (mut port, _, mut raw) = raw_pair(Limits::default());
        let mut header = encoded(1, &packet(4))[..HEADER].to_vec();
        match defect {
            0 => header[0] = 0,
            1 => header[2] = 2,
            2 => header[3] = 2,
            3 => header[4..].copy_from_slice(&65537u32.to_be_bytes()),
            4 => header[4..].copy_from_slice(&0u32.to_be_bytes()),
            _ => header[4..].copy_from_slice(&19u32.to_be_bytes()),
        }
        raw.write_all(&header).unwrap();
        assert_eq!(
            port.receive().unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        assert!(port.payload.is_empty());
        assert_eq!(
            port.receive().unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }
}
#[test]
fn worker_ipc_packet_family_and_minimum_lengths_are_validated() {
    for payload in [vec![0; 20], vec![0x60; 20], vec![0x40; 19]] {
        let (mut port, _, mut raw) = raw_pair(Limits::default());
        raw.write_all(&encoded(1, &payload)).unwrap();
        assert_eq!(
            port.receive().unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }
    let (mut port, _, mut raw) = raw_pair(Limits::default());
    assert!(port.send(&[]).is_err());
    assert!(port.send(&vec![0x40; 65537]).is_err());
    raw.set_nonblocking(true).unwrap();
    let mut byte = [0];
    assert_eq!(
        raw.read(&mut byte).unwrap_err().kind(),
        io::ErrorKind::WouldBlock
    );
}
#[test]
fn worker_ipc_cancel_partial_frame_clears_owned_queues_and_does_not_touch_other_channel() {
    let (mut port, cancel, mut raw) = raw_pair(Limits::default());
    raw.write_all(b"AP").unwrap();
    assert!(port.receive().unwrap().is_none());
    port.enqueue(&packet(6)).unwrap();
    let (mut other, c) = UnixStream::pair().unwrap();
    let mut peer = c;
    cancel.cancel();
    assert_eq!(
        port.receive().unwrap_err().kind(),
        io::ErrorKind::Interrupted
    );
    assert_eq!(port.queued(), (0, 0));
    assert!(port.send(&packet(4)).is_err());
    let mut byte = [0];
    assert_eq!(raw.read(&mut byte).unwrap(), 0);
    other.write_all(b"z").unwrap();
    peer.read_exact(&mut byte).unwrap();
    assert_eq!(byte, [b'z']);
}
#[test]
fn worker_ipc_drop_closes_peer_even_when_cancel_handle_is_retained() {
    let (port, _retained, mut raw) = raw_pair(Limits::default());
    drop(port);
    let mut byte = [0];
    assert_eq!(raw.read(&mut byte).unwrap(), 0);
}
#[test]
fn worker_ipc_queue_counts_and_byte_budget_refuse_before_allocating_another_frame() {
    let limits = Limits {
        max_packet_bytes: 40,
        max_queued_packets: 2,
        max_queued_bytes: 64,
        max_io_ops: 1,
    };
    let (mut port, _, _) = raw_pair(limits);
    port.enqueue(&packet(6)).unwrap();
    assert_eq!(port.queued(), (1, 48));
    assert_eq!(
        port.enqueue(&packet(4)).unwrap_err().kind(),
        io::ErrorKind::WouldBlock
    );
    assert_eq!(port.queued(), (1, 48));
    let limits = Limits {
        max_packet_bytes: 40,
        max_queued_packets: 1,
        max_queued_bytes: 128,
        max_io_ops: 1,
    };
    let (mut port, _, _) = raw_pair(limits);
    port.enqueue(&packet(4)).unwrap();
    assert_eq!(
        port.enqueue(&packet(4)).unwrap_err().kind(),
        io::ErrorKind::WouldBlock
    );
    assert_eq!(port.queued(), (1, 28));
}
#[test]
fn worker_ipc_actual_socket_backpressure_is_bounded_and_preserves_accepted_fifo() {
    let (a, b) = UnixStream::pair().unwrap();
    socket2::SockRef::from(&a)
        .set_send_buffer_size(1024)
        .unwrap();
    let limits = Limits {
        max_packet_bytes: 40,
        max_queued_packets: 1,
        max_queued_bytes: 48,
        max_io_ops: 1,
    };
    let (mut sender, _) = PacketPort::new(a, Role::Parent, limits).unwrap();
    let (mut receiver, _) = PacketPort::new(b, Role::Worker, Limits::default()).unwrap();
    let mut accepted = 0;
    loop {
        match sender.send(&packet(6)) {
            Ok(()) => accepted += 1,
            Err(e) => {
                assert_eq!(e.kind(), io::ErrorKind::WouldBlock);
                break;
            }
        }
        assert!(accepted < 4096);
        assert!(sender.queued().0 <= 1);
        assert!(sender.queued().1 <= 48);
    }
    let end = Instant::now() + Duration::from_secs(2);
    let mut received = 0;
    while received < accepted {
        sender.flush_pending().unwrap();
        if let Some(p) = receiver.receive().unwrap() {
            assert_eq!(p, packet(6));
            received += 1;
        }
        assert!(Instant::now() < end);
    }
    assert_eq!(sender.queued(), (0, 0));
    assert!(receiver.receive().unwrap().is_none());
}
#[test]
fn worker_ipc_send_shares_one_write_budget_across_existing_and_new_frames() {
    let limits = Limits {
        max_io_ops: 1,
        ..Limits::default()
    };
    let (mut port, _, mut raw) = raw_pair(limits);
    port.enqueue(&packet(4)).unwrap();
    port.send(&packet(6)).unwrap();
    let queued = port
        .output
        .front()
        .expect("new frame waits after old frame consumes one syscall");
    assert_eq!(queued.written, 0);
    assert_eq!(port.queued(), (1, 48));
    let mut first = vec![0; 28];
    raw.read_exact(&mut first).unwrap();
    assert_eq!(first, encoded(2, &packet(4)));
    raw.set_nonblocking(true).unwrap();
    let mut byte = [0];
    assert_eq!(
        raw.read(&mut byte).unwrap_err().kind(),
        io::ErrorKind::WouldBlock
    );
    port.flush_pending().unwrap();
    let mut second = vec![0; 48];
    raw.read_exact(&mut second).unwrap();
    assert_eq!(second, encoded(2, &packet(6)));
}
#[test]
fn worker_ipc_actual_partial_write_drains_one_large_frame_without_duplication() {
    let (a, b) = UnixStream::pair().unwrap();
    socket2::SockRef::from(&a)
        .set_send_buffer_size(1024)
        .unwrap();
    let limits = Limits {
        max_io_ops: 1,
        ..Limits::default()
    };
    let (mut sender, _) = PacketPort::new(a, Role::Parent, limits).unwrap();
    let (mut receiver, _) = PacketPort::new(b, Role::Worker, Limits::default()).unwrap();
    let mut large = vec![0x5a; 65536];
    large[0] = 0x60;
    sender.send(&large).unwrap();
    let pending = sender
        .output
        .front()
        .expect("large frame must exceed owned socket buffer");
    assert!(pending.written > 0 && pending.written < pending.bytes.len());
    assert_eq!(sender.queued(), (1, 65536 + HEADER));
    let end = Instant::now() + Duration::from_secs(2);
    let received = loop {
        sender.flush_pending().unwrap();
        if let Some(p) = receiver.receive().unwrap() {
            break p;
        }
        assert!(Instant::now() < end);
    };
    assert_eq!(received, large);
    assert_eq!(sender.queued(), (0, 0));
    assert!(receiver.receive().unwrap().is_none());
}
#[test]
fn worker_ipc_poll_budget_and_limit_admission_are_finite() {
    let limits = Limits {
        max_io_ops: 1,
        ..Limits::default()
    };
    let (mut port, _, mut raw) = raw_pair(limits);
    raw.write_all(&encoded(1, &packet(4))).unwrap();
    assert!(port.receive().unwrap().is_none());
    assert_eq!(port.receive().unwrap().unwrap(), packet(4));
    for l in [
        Limits {
            max_packet_bytes: 39,
            ..limits
        },
        Limits {
            max_packet_bytes: 65537,
            ..limits
        },
        Limits {
            max_io_ops: 0,
            ..limits
        },
        Limits {
            max_io_ops: 65,
            ..limits
        },
        Limits {
            max_queued_packets: 0,
            ..limits
        },
        Limits {
            max_queued_packets: 513,
            ..limits
        },
        Limits {
            max_queued_bytes: MAX_QUEUE_BYTES + 1,
            ..limits
        },
        Limits {
            max_queued_bytes: 40,
            ..limits
        },
    ] {
        let (a, _) = UnixStream::pair().unwrap();
        assert!(PacketPort::new(a, Role::Worker, l).is_err());
    }
}
