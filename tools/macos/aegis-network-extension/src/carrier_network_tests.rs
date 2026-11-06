//! v40 (CP-D3 M1): the access network key from the path monitor's facts.
use super::*;

fn interface(name: &str, index: u32, kind: InterfaceKind) -> PathInterface {
    PathInterface {
        name: name.into(),
        index,
        kind,
    }
}

#[test]
fn the_key_is_stable_per_network_and_differs_by_interface_type_name_gateway_and_salt() {
    let salt = [9; 32];
    let gateway: IpAddr = "192.168.1.1".parse().unwrap();
    let router6: IpAddr = "fe80::1".parse().unwrap();
    let home = derive(&salt, InterfaceKind::Wifi, "en0", &[gateway, router6]);
    assert_ne!(home, NetworkKey::UNKNOWN);
    // Order and repeats of the gateways do not matter.
    assert_eq!(
        home,
        derive(
            &salt,
            InterfaceKind::Wifi,
            "en0",
            &[router6, gateway, gateway]
        )
    );
    for other in [
        derive(&salt, InterfaceKind::Wired, "en0", &[gateway, router6]),
        derive(&salt, InterfaceKind::Wifi, "en7", &[gateway, router6]),
        derive(
            &salt,
            InterfaceKind::Wifi,
            "en0",
            &["192.168.1.254".parse().unwrap()],
        ),
        derive(&salt, InterfaceKind::Wifi, "en0", &[]),
        derive(&[8; 32], InterfaceKind::Wifi, "en0", &[gateway, router6]),
    ] {
        assert_ne!(home, other);
    }
    // The label is four bytes of the hash, never an address.
    assert_eq!(home.label().len(), 8);
    assert!(!home.label().contains("192"));
}

#[test]
fn a_path_key_uses_the_first_eligible_interface_and_is_unknown_without_one() {
    let salt = [3; 32];
    let gateway: IpAddr = "10.0.0.1".parse().unwrap();
    let interfaces = [
        interface("utun4", 20, InterfaceKind::Other),
        interface("awdl0", 11, InterfaceKind::Wifi),
        interface("en0", 4, InterfaceKind::Wifi),
        interface("en7", 9, InterfaceKind::Wired),
    ];
    assert_eq!(
        path_key(&salt, true, &interfaces, &[gateway]),
        derive(&salt, InterfaceKind::Wifi, "en0", &[gateway])
    );
    assert_eq!(
        path_key(&salt, false, &interfaces, &[gateway]),
        NetworkKey::UNKNOWN
    );
    assert_eq!(
        path_key(&salt, true, &interfaces[..2], &[gateway]),
        NetworkKey::UNKNOWN
    );
}

#[test]
fn socket_addresses_of_both_families_and_no_other_are_read() {
    let mut v4: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    v4.sin_family = libc::AF_INET as libc::sa_family_t;
    v4.sin_len = std::mem::size_of::<libc::sockaddr_in>() as u8;
    v4.sin_addr.s_addr = u32::from_ne_bytes([192, 168, 7, 1]);
    let read = unsafe { socket_ip((&v4 as *const libc::sockaddr_in).cast()) };
    assert_eq!(read, Some("192.168.7.1".parse().unwrap()));
    let mut v6: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
    v6.sin6_family = libc::AF_INET6 as libc::sa_family_t;
    v6.sin6_len = std::mem::size_of::<libc::sockaddr_in6>() as u8;
    v6.sin6_addr.s6_addr = "fe80::1".parse::<std::net::Ipv6Addr>().unwrap().octets();
    let read = unsafe { socket_ip((&v6 as *const libc::sockaddr_in6).cast()) };
    assert_eq!(read, Some("fe80::1".parse().unwrap()));
    let mut unix: libc::sockaddr = unsafe { std::mem::zeroed() };
    unix.sa_family = libc::AF_UNIX as libc::sa_family_t;
    assert_eq!(unsafe { socket_ip(&unix) }, None);
    assert_eq!(unsafe { socket_ip(std::ptr::null()) }, None);
}

#[test]
fn the_salt_is_random_per_process_and_stable_within_it() {
    assert_eq!(salt(), salt());
    assert_ne!(salt(), &[0; 32]);
}

/// The real Network.framework monitor on this Mac: a satisfied physical
/// path publishes a key (run by hand with `--ignored`; it needs a network,
/// which a CI runner may not have).
#[test]
#[ignore = "needs this Mac's satisfied physical path"]
fn the_process_path_monitor_publishes_this_macs_network_key() {
    start();
    start();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while current() == NetworkKey::UNKNOWN && std::time::Instant::now() < deadline {
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    let key = current();
    assert_ne!(key, NetworkKey::UNKNOWN);
    // Stable while the path is: a second read is the same key.
    std::thread::sleep(std::time::Duration::from_millis(200));
    assert_eq!(current(), key);
}
