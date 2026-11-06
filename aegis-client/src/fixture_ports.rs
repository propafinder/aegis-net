//! Test-only socket ownership; never changes production listener policy.

use std::io;
use std::net::{SocketAddr, TcpListener, UdpSocket};

const MAX_CANDIDATES: usize = 16;

pub(crate) fn reserve_dual_protocol_target() -> io::Result<(TcpListener, UdpSocket)> {
    reserve_with(
        || TcpListener::bind("127.0.0.1:0"),
        || UdpSocket::bind("127.0.0.1:0"),
        TcpListener::bind,
        UdpSocket::bind,
    )
}

fn reserve_with<T0, U0, TAt, UAt>(
    mut tcp_zero: T0,
    mut udp_zero: U0,
    mut tcp_at: TAt,
    mut udp_at: UAt,
) -> io::Result<(TcpListener, UdpSocket)>
where
    T0: FnMut() -> io::Result<TcpListener>,
    U0: FnMut() -> io::Result<UdpSocket>,
    TAt: FnMut(SocketAddr) -> io::Result<TcpListener>,
    UAt: FnMut(SocketAddr) -> io::Result<UdpSocket>,
{
    let mut rejected_tcp = Vec::with_capacity(MAX_CANDIDATES / 2);
    let mut rejected_udp = Vec::with_capacity(MAX_CANDIDATES / 2);
    let mut rejections = Vec::with_capacity(MAX_CANDIDATES);
    let mut last_rejection = None;
    for candidate in 0..MAX_CANDIDATES {
        if candidate % 2 == 0 {
            // Keep a rejected TCP socket alive so TCP :0 cannot draw it again.
            let tcp = tcp_zero()?;
            let address = tcp.local_addr()?;
            if let Some(index) = rejected_udp.iter().position(|(held, _)| *held == address) {
                let (_, udp) = rejected_udp.swap_remove(index);
                return Ok((tcp, udp));
            }
            match udp_at(address) {
                Ok(udp) => return Ok((tcp, udp)),
                Err(error) if candidate_rejection(&error) => {
                    rejections.push((
                        candidate + 1,
                        "tcp",
                        address.port(),
                        error.kind(),
                        error.raw_os_error(),
                    ));
                    last_rejection = Some(error);
                    rejected_tcp.push((address, tcp));
                }
                Err(error) => return Err(error),
            }
        } else {
            // The reverse draw covers UDP ports that TCP :0 did not select.
            let udp = udp_zero()?;
            let address = udp.local_addr()?;
            if let Some(index) = rejected_tcp.iter().position(|(held, _)| *held == address) {
                let (_, tcp) = rejected_tcp.swap_remove(index);
                return Ok((tcp, udp));
            }
            match tcp_at(address) {
                Ok(tcp) => return Ok((tcp, udp)),
                Err(error) if candidate_rejection(&error) => {
                    rejections.push((
                        candidate + 1,
                        "udp",
                        address.port(),
                        error.kind(),
                        error.raw_os_error(),
                    ));
                    last_rejection = Some(error);
                    rejected_udp.push((address, udp));
                }
                Err(error) => return Err(error),
            }
        }
    }
    // Bounded, test-only context. Keep the original final OS error intact.
    for (candidate, primary, port, kind, raw_os_error) in rejections {
        eprintln!(
            "fixture_port_rejection candidate={candidate} primary={primary} port={port} kind={kind:?} raw_os_error={raw_os_error:?}"
        );
    }
    Err(last_rejection.expect("positive candidate bound"))
}

fn candidate_rejection(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::AddrInUse | io::ErrorKind::PermissionDenied
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::{Cell, RefCell};
    use std::collections::HashSet;

    #[test]
    fn dual_protocol_target_holds_both_namespaces() {
        let (tcp, udp) = reserve_dual_protocol_target().unwrap();
        let address = tcp.local_addr().unwrap();
        assert_eq!(udp.local_addr().unwrap(), address);
        assert_ne!(address.port(), 0);
        assert!(UdpSocket::bind(address).is_err());
        assert!(TcpListener::bind(address).is_err());
        drop(tcp);
        drop(udp);
        let _released_udp = UdpSocket::bind(address).unwrap();
        let _released_tcp = TcpListener::bind(address).unwrap();
    }

    #[test]
    fn denied_tcp_allocation_is_fatal_without_udp_attempt() {
        let mut draws = 0;
        let error = reserve_with(
            || {
                draws += 1;
                Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "TCP allocation denied",
                ))
            },
            || panic!("UDP :0 must not be attempted"),
            |_| panic!("explicit TCP must not be attempted"),
            |_| panic!("explicit UDP must not be attempted"),
        )
        .unwrap_err();
        assert_eq!(draws, 1);
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(error.to_string(), "TCP allocation denied");
    }

    #[test]
    fn candidate_udp_rejection_selects_next_candidate() {
        for rejection in [io::ErrorKind::PermissionDenied, io::ErrorKind::AddrInUse] {
            let first = TcpListener::bind("127.0.0.1:0").unwrap();
            let first_address = first.local_addr().unwrap();
            let (second_tcp, second_udp) = reserve_dual_protocol_target().unwrap();
            let second_address = second_tcp.local_addr().unwrap();
            assert_ne!(first_address, second_address);
            let first = RefCell::new(Some(first));
            let second_tcp = RefCell::new(Some(second_tcp));
            let second_udp = RefCell::new(Some(second_udp));
            let calls = Cell::new(0);
            let (tcp, udp) = reserve_with(
                || {
                    first
                        .borrow_mut()
                        .take()
                        .ok_or_else(|| io::Error::other("extra TCP draw"))
                },
                || {
                    // The rejected primary remains owned during the second draw.
                    assert!(TcpListener::bind(first_address).is_err());
                    second_udp
                        .borrow_mut()
                        .take()
                        .ok_or_else(|| io::Error::other("extra UDP draw"))
                },
                |address| {
                    assert_eq!(address, second_address);
                    calls.set(calls.get() + 1);
                    second_tcp
                        .borrow_mut()
                        .take()
                        .ok_or_else(|| io::Error::other("extra TCP bind"))
                },
                |address| {
                    assert_eq!(address, first_address);
                    calls.set(calls.get() + 1);
                    assert!(TcpListener::bind(address).is_err());
                    Err(io::Error::new(rejection, "candidate rejected"))
                },
            )
            .unwrap();
            assert_eq!(calls.get(), 2);
            assert_eq!(tcp.local_addr().unwrap(), second_address);
            assert_eq!(udp.local_addr().unwrap(), second_address);
        }
    }

    #[test]
    fn retained_tcp_completes_reverse_draw_without_rebinding() {
        let (first_tcp, first_udp) = reserve_dual_protocol_target().unwrap();
        let address = first_tcp.local_addr().unwrap();
        let first_tcp = RefCell::new(Some(first_tcp));
        let first_udp = RefCell::new(Some(first_udp));
        let (tcp, udp) = reserve_with(
            || {
                first_tcp
                    .borrow_mut()
                    .take()
                    .ok_or_else(|| io::Error::other("extra TCP draw"))
            },
            || {
                first_udp
                    .borrow_mut()
                    .take()
                    .ok_or_else(|| io::Error::other("extra UDP draw"))
            },
            |_| panic!("retained TCP must complete the pair"),
            |candidate| {
                assert_eq!(candidate, address);
                Err(io::Error::new(
                    io::ErrorKind::AddrInUse,
                    "injected rejection",
                ))
            },
        )
        .unwrap();
        assert_eq!(tcp.local_addr().unwrap(), address);
        assert_eq!(udp.local_addr().unwrap(), address);
    }

    #[test]
    fn retained_udp_completes_forward_draw_without_rebinding() {
        let (first_tcp, _first_udp) = reserve_dual_protocol_target().unwrap();
        let (later_tcp, later_udp) = reserve_dual_protocol_target().unwrap();
        let address = later_tcp.local_addr().unwrap();
        let tcp_draws = RefCell::new([Some(first_tcp), Some(later_tcp)].into_iter());
        let later_udp = RefCell::new(Some(later_udp));
        let (tcp, udp) = reserve_with(
            || {
                tcp_draws
                    .borrow_mut()
                    .next()
                    .unwrap()
                    .ok_or_else(|| io::Error::other("extra TCP draw"))
            },
            || {
                later_udp
                    .borrow_mut()
                    .take()
                    .ok_or_else(|| io::Error::other("extra UDP draw"))
            },
            |candidate| {
                assert_eq!(candidate, address);
                Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "injected TCP rejection",
                ))
            },
            |_| {
                Err(io::Error::new(
                    io::ErrorKind::AddrInUse,
                    "injected UDP rejection",
                ))
            },
        )
        .unwrap();
        assert_eq!(tcp.local_addr().unwrap(), address);
        assert_eq!(udp.local_addr().unwrap(), address);
    }

    #[test]
    fn denied_udp_zero_allocation_is_fatal_after_first_rejection() {
        let first = TcpListener::bind("127.0.0.1:0").unwrap();
        let first = RefCell::new(Some(first));
        let error = reserve_with(
            || {
                first
                    .borrow_mut()
                    .take()
                    .ok_or_else(|| io::Error::other("extra TCP draw"))
            },
            || {
                Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "UDP :0 denied",
                ))
            },
            |_| panic!("explicit TCP must not be attempted"),
            |_| {
                Err(io::Error::new(
                    io::ErrorKind::AddrInUse,
                    "first candidate rejected",
                ))
            },
        )
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(error.to_string(), "UDP :0 denied");
    }

    #[test]
    fn unexpected_udp_error_is_fatal_without_redraw() {
        let mut calls = 0;
        let error = reserve_with(
            || TcpListener::bind("127.0.0.1:0"),
            || panic!("UDP :0 must not be attempted"),
            |_| panic!("explicit TCP must not be attempted"),
            |_| {
                calls += 1;
                Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "unexpected UDP error",
                ))
            },
        )
        .unwrap_err();
        assert_eq!(calls, 1);
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn unexpected_tcp_error_is_fatal_without_redraw() {
        let first = RefCell::new(Some(TcpListener::bind("127.0.0.1:0").unwrap()));
        let (_second_tcp, second_udp) = reserve_dual_protocol_target().unwrap();
        let second_udp = RefCell::new(Some(second_udp));
        let tcp_draws = Cell::new(0);
        let udp_draws = Cell::new(0);
        let error = reserve_with(
            || {
                tcp_draws.set(tcp_draws.get() + 1);
                assert_eq!(tcp_draws.get(), 1);
                first
                    .borrow_mut()
                    .take()
                    .ok_or_else(|| io::Error::other("extra TCP draw"))
            },
            || {
                udp_draws.set(udp_draws.get() + 1);
                assert_eq!(udp_draws.get(), 1);
                second_udp
                    .borrow_mut()
                    .take()
                    .ok_or_else(|| io::Error::other("extra UDP draw"))
            },
            |_| {
                Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "unexpected TCP error",
                ))
            },
            |_| {
                Err(io::Error::new(
                    io::ErrorKind::AddrInUse,
                    "first candidate rejected",
                ))
            },
        )
        .unwrap_err();
        assert_eq!(tcp_draws.get(), 1);
        assert_eq!(udp_draws.get(), 1);
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert_eq!(error.to_string(), "unexpected TCP error");
    }

    #[test]
    fn exhausted_candidates_return_original_final_error() {
        // Each sibling stays owned while its corresponding primary is injected.
        let pairs: Vec<_> = (0..MAX_CANDIDATES)
            .map(|_| reserve_dual_protocol_target().unwrap())
            .collect();
        let addresses: Vec<_> = pairs
            .iter()
            .map(|(tcp, _)| tcp.local_addr().unwrap())
            .collect();
        assert_eq!(
            addresses.iter().copied().collect::<HashSet<_>>().len(),
            MAX_CANDIDATES
        );
        let owned: Vec<_> = pairs
            .into_iter()
            .map(|(tcp, udp)| (Some(tcp), Some(udp)))
            .collect();
        let owned = RefCell::new(owned);
        let next_tcp = Cell::new(0);
        let next_udp = Cell::new(1);
        let calls = Cell::new(0);
        let seen = RefCell::new(HashSet::new());
        let error = reserve_with(
            || {
                let index = next_tcp.get();
                next_tcp.set(index + 2);
                owned.borrow_mut()[index]
                    .0
                    .take()
                    .ok_or_else(|| io::Error::other("extra TCP draw"))
            },
            || {
                let index = next_udp.get();
                next_udp.set(index + 2);
                owned.borrow_mut()[index]
                    .1
                    .take()
                    .ok_or_else(|| io::Error::other("extra UDP draw"))
            },
            |address| {
                assert!(seen.borrow_mut().insert(address));
                let call = calls.get() + 1;
                calls.set(call);
                Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!("denied candidate {call}"),
                ))
            },
            |address| {
                assert!(seen.borrow_mut().insert(address));
                let call = calls.get() + 1;
                calls.set(call);
                Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!("denied candidate {call}"),
                ))
            },
        )
        .unwrap_err();
        assert_eq!(calls.get(), MAX_CANDIDATES);
        assert_eq!(seen.borrow().len(), MAX_CANDIDATES);
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(error.to_string(), "denied candidate 16");
    }
}
