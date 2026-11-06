//! B-06 S16f relay interface resolution and bound relay sockets. Only
//! loopback is ever connected; the non-loopback resolution sends nothing.
use super::*;
use std::{path::Path, time::Duration};

fn entry(name: &str, address: &str, up: bool, loopback: bool) -> InterfaceAddress {
    InterfaceAddress {
        name: name.into(),
        address: address.parse().unwrap(),
        up,
        loopback,
        point_to_point: false,
    }
}

fn host_like() -> Vec<InterfaceAddress> {
    vec![
        entry("lo0", "127.0.0.1", true, true),
        entry("lo0", "::1", true, true),
        entry("en0", "192.168.1.20", true, false),
        entry("en0", "2001:db8::20", true, false),
        entry("en7", "10.20.0.7", true, false),
        entry("utun4", "198.19.0.2", true, false),
        entry("utun4", "fd00::2", true, false),
        entry("ipsec0", "172.16.0.2", true, false),
        entry("en9", "10.30.0.9", false, false),
        entry("bridge100", "192.168.64.1", true, false),
        // Loopback or unspecified sources on an interface that would
        // otherwise pass: only the source check refuses them.
        entry("en3", "127.0.0.2", true, false),
        entry("en4", "0.0.0.0", true, false),
        entry("en4", "::", true, false),
    ]
}

#[test]
fn ice_udp_socket_is_physically_bound_before_runtime_handoff() {
    let interface = RelayInterface::loopback_for_test();
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    assert_eq!(bound_index(socket.as_raw_fd(), false).unwrap(), 0);
    assert!(bind_ice_udp(&socket, &interface, "127.0.0.1".parse().unwrap()).is_ok());
    assert_eq!(
        bound_index(socket.as_raw_fd(), false).unwrap(),
        interface.index()
    );
    assert!(bind_ice_udp(&socket, &interface, "127.0.0.2".parse().unwrap()).is_err());
    assert!(bind_ice_udp(
        &socket,
        &RelayInterface::for_test("en0", 7),
        "127.0.0.1".parse().unwrap()
    )
    .is_err());
}

#[test]
fn relay_interface_selects_the_one_physical_holder_of_the_route_source() {
    let list = host_like();
    for (local, name) in [
        ("192.168.1.20", "en0"),
        ("2001:db8::20", "en0"),
        ("10.20.0.7", "en7"),
        ("192.168.64.1", "bridge100"),
    ] {
        assert_eq!(
            select_interface(local.parse().unwrap(), &list),
            Ok(name),
            "{local}"
        );
    }
}

#[test]
fn quic_source_uses_kernel_selected_ipv6_among_multiple_physical_addresses() {
    let interface = RelayInterface::for_test("en0", 4);
    let peer: SocketAddr = "[2001:db8:ffff::1]:443".parse().unwrap();
    let addresses = [
        entry("en0", "2001:db8::20", true, false),
        entry("en0", "2001:db8::21", true, false),
    ];
    assert_eq!(
        select_bound_udp_source(
            "2001:db8::21".parse().unwrap(),
            peer,
            &interface,
            &addresses
        )
        .unwrap(),
        "2001:db8::21".parse::<IpAddr>().unwrap()
    );
    for bad in ["2001:db8::22", "::", "::1"] {
        assert!(
            select_bound_udp_source(bad.parse().unwrap(), peer, &interface, &addresses).is_err()
        );
    }
    let foreign = [
        entry("en0", "2001:db8::21", true, false),
        entry("en7", "2001:db8::21", true, false),
    ];
    assert!(
        select_bound_udp_source("2001:db8::21".parse().unwrap(), peer, &interface, &foreign)
            .is_err()
    );
    let down = [entry("en0", "2001:db8::21", false, false)];
    assert!(
        select_bound_udp_source("2001:db8::21".parse().unwrap(), peer, &interface, &down).is_err()
    );
    let tunnel = RelayInterface::for_test("utun4", 9);
    assert!(
        select_bound_udp_source("2001:db8::21".parse().unwrap(), peer, &tunnel, &addresses)
            .is_err()
    );
    assert!(select_bound_udp_source(
        "2001:db8::21".parse().unwrap(),
        "[::]:443".parse().unwrap(),
        &interface,
        &addresses
    )
    .is_err());
}

#[test]
fn quic_loopback_probe_produces_a_distinct_unconnected_bound_socket() {
    let interface = RelayInterface::loopback_for_test();
    for peer in ["127.0.0.1:443", "[::1]:443"] {
        let peer: SocketAddr = peer.parse().unwrap();
        assert_eq!(
            physical_source_for_peer(peer, &interface).unwrap(),
            peer.ip()
        );
        let socket = bound_udp_socket(peer, &interface).unwrap();
        assert_eq!(socket.local_addr().unwrap().ip(), peer.ip());
        assert_ne!(socket.local_addr().unwrap().port(), 0);
        assert_eq!(
            bound_index(socket.as_raw_fd(), peer.is_ipv6()).unwrap(),
            interface.index()
        );
        assert_eq!(
            socket.peer_addr().unwrap_err().kind(),
            io::ErrorKind::NotConnected
        );
    }
}

#[test]
fn signed_media_source_probe_refuses_foreign_or_unspecified_peer() {
    let interface = RelayInterface::loopback_for_test();
    for peer in ["0.0.0.0:443", "[::]:443", "127.0.0.1:0"] {
        assert!(physical_source_for_peer(peer.parse().unwrap(), &interface).is_err());
    }
    let foreign = RelayInterface::for_test("en99", interface.index());
    assert!(physical_source_for_peer("127.0.0.1:443".parse().unwrap(), &foreign).is_err());
}

#[test]
fn relay_interface_refuses_tunnel_ipsec_loopback_down_unknown_and_ambiguous() {
    let list = host_like();
    for local in [
        // Unspecified or loopback route sources.
        "0.0.0.0",
        "::",
        "127.0.0.1",
        "::1",
        "127.0.0.2",
        // This or another VPN's tunnel, IPsec.
        "198.19.0.2",
        "fd00::2",
        "172.16.0.2",
        // A down interface, and an address no interface holds.
        "10.30.0.9",
        "10.99.0.1",
    ] {
        assert_eq!(
            select_interface(local.parse().unwrap(), &list),
            Err(UNRESOLVED),
            "{local}"
        );
    }
    // A loopback-flagged interface under any name, and a tunnel or loopback
    // name without the flag, are refused.
    for (name, loopback) in [
        ("en5", true),
        ("utun0", false),
        ("utun12", false),
        ("ipsec3", false),
        ("lo1", false),
        // Other VPNs' tunnels and Apple peer-to-peer links.
        ("ppp0", false),
        ("tun0", false),
        ("tap0", false),
        ("gif0", false),
        ("stf0", false),
        ("feth2734", false),
        ("awdl0", false),
        ("llw0", false),
        ("", false),
    ] {
        let list = [entry(name, "10.40.0.4", true, loopback)];
        assert_eq!(
            select_interface("10.40.0.4".parse().unwrap(), &list),
            Err(UNRESOLVED),
            "{name}"
        );
    }
    // The same source on two differently named interfaces is ambiguous; on
    // one interface listed twice it is not.
    let twice = [
        entry("en0", "10.50.0.5", true, false),
        entry("en1", "10.50.0.5", true, false),
    ];
    assert_eq!(
        select_interface("10.50.0.5".parse().unwrap(), &twice),
        Err(UNRESOLVED)
    );
    let repeated = [
        entry("en0", "10.50.0.5", true, false),
        entry("en0", "10.50.0.5", true, false),
    ];
    assert_eq!(
        select_interface("10.50.0.5".parse().unwrap(), &repeated),
        Ok("en0")
    );
    for name in ["en0", "en7", "pdp_ip0", "bridge100"] {
        assert!(!refused_name(name), "{name}");
    }
    // A point-to-point interface is refused whatever its name; the same
    // entry without the flag is accepted.
    for name in ["en8", "pdp_ip1", "bridge101"] {
        let mut flagged = entry(name, "10.60.0.6", true, false);
        assert_eq!(
            select_interface("10.60.0.6".parse().unwrap(), &[flagged.clone()]),
            Ok(name),
            "{name}"
        );
        flagged.point_to_point = true;
        assert_eq!(
            select_interface("10.60.0.6".parse().unwrap(), &[flagged]),
            Err(UNRESOLVED),
            "{name}"
        );
    }
}

#[test]
fn relay_interface_getifaddrs_lists_loopback_and_production_refuses_it() {
    let list = interface_addresses().unwrap();
    let lo = |address: &str| {
        list.iter()
            .any(|e| e.name == "lo0" && e.address == address.parse::<IpAddr>().unwrap())
    };
    assert!(lo("127.0.0.1"), "{list:?}");
    assert!(lo("::1"), "{list:?}");
    assert!(list
        .iter()
        .filter(|e| e.name == "lo0")
        .all(|e| e.loopback && e.up && !e.point_to_point));
    // Every utun entry carries the point-to-point flag (macOS sets it on
    // utun); lo0 does not.
    assert!(list
        .iter()
        .filter(|e| e.name.starts_with("utun"))
        .all(|e| e.point_to_point));
    // A loopback relay never resolves to a relay interface.
    for relay in ["127.0.0.1:443", "[::1]:443"] {
        assert_eq!(
            resolve_relay_interface(relay.parse().unwrap()),
            Err(UNRESOLVED),
            "{relay}"
        );
    }
}

#[test]
fn relay_interface_resolves_a_non_loopback_relay_to_a_physical_interface_or_refuses() {
    // TEST-NET-1: a connected UDP socket sends nothing. Without a route, or
    // with a tunnel as the route, the stable refusal is the only answer.
    let relay: SocketAddr = "192.0.2.1:443".parse().unwrap();
    match resolve_relay_interface(relay) {
        Ok(interface) => {
            assert!(!refused_name(interface.name()), "{interface:?}");
            assert_ne!(interface.index(), 0);
            assert_eq!(name_to_index(interface.name()), Some(interface.index()));
            let source = route_source(relay).unwrap();
            let list = interface_addresses().unwrap();
            assert_eq!(select_interface(source, &list), Ok(interface.name()));
        }
        Err(code) => assert_eq!(code, UNRESOLVED),
    }
}

#[test]
fn relay_interface_loopback_override_names_lo0() {
    let lo = RelayInterface::loopback_for_test();
    assert_eq!(lo.name(), "lo0");
    assert_eq!(Some(lo.index()), name_to_index("lo0"));
    assert_eq!(name_to_index("aegis-no-such-if0"), None);
}

async fn bound_round_trip(listen: &str, ipv6: bool) {
    let listener = tokio::net::TcpListener::bind(listen).await.unwrap();
    let address = listener.local_addr().unwrap();
    let lo = RelayInterface::loopback_for_test();
    // An unbound socket reads 0; the helper's socket is bound before connect.
    let plain = if ipv6 {
        TcpSocket::new_v6().unwrap()
    } else {
        TcpSocket::new_v4().unwrap()
    };
    assert_eq!(bound_index(plain.as_raw_fd(), ipv6).unwrap(), 0);
    let socket = bound_socket(address, &lo).unwrap();
    assert_eq!(bound_index(socket.as_raw_fd(), ipv6).unwrap(), lo.index());
    let stream = socket.connect(address).await.unwrap();
    assert_eq!(bound_index(stream.as_raw_fd(), ipv6).unwrap(), lo.index());
    let (_accepted, _) = listener.accept().await.unwrap();
    // connect_bound is the same socket.
    let stream = connect_bound(address, &lo).await.unwrap();
    assert_eq!(stream.peer_addr().unwrap(), address);
    assert_eq!(bound_index(stream.as_raw_fd(), ipv6).unwrap(), lo.index());
}

#[tokio::test]
async fn relay_socket_sets_ip_bound_if_before_connect_for_ipv4() {
    bound_round_trip("127.0.0.1:0", false).await;
}

#[tokio::test]
async fn relay_socket_sets_ipv6_bound_if_before_connect_for_ipv6() {
    bound_round_trip("[::1]:0", true).await;
}

#[tokio::test]
async fn relay_socket_refuses_an_unbinding_index_and_a_missing_interface() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    // Index 0 would clear the binding: refused before any socket connects.
    let zero = RelayInterface::for_test("en0", 0);
    assert_eq!(
        bound_socket(address, &zero).err().unwrap().kind(),
        io::ErrorKind::InvalidInput
    );
    assert_eq!(
        connect_bound(address, &zero).await.err().unwrap().kind(),
        io::ErrorKind::InvalidInput
    );
    // An index no interface has never connects: the kernel refuses the
    // binding as a vanished interface (ENXIO), which is logged as lost.
    let missing = RelayInterface::for_test("en99", 0x7fff_0000);
    let dial = tokio::time::timeout(Duration::from_secs(1), connect_bound(address, &missing));
    let error = dial.await.unwrap().err().unwrap();
    assert_eq!(error.raw_os_error(), Some(libc::ENXIO));
    assert!(interface_lost(&error));
    // Nothing reached the listener.
    let accepted = tokio::time::timeout(Duration::from_millis(100), listener.accept()).await;
    assert!(accepted.is_err());
}

#[test]
fn relay_socket_names_only_vanished_interface_errnos_as_lost() {
    for errno in [libc::ENETDOWN, libc::EADDRNOTAVAIL, libc::ENXIO] {
        assert!(interface_lost(&io::Error::from_raw_os_error(errno)));
    }
    for errno in [libc::ECONNREFUSED, libc::ETIMEDOUT, libc::EHOSTUNREACH] {
        assert!(!interface_lost(&io::Error::from_raw_os_error(errno)));
    }
    assert!(!interface_lost(&io::ErrorKind::TimedOut.into()));
}

/// Production source of one file: everything before its test module.
fn production_part(text: &str) -> &str {
    let lines: Vec<&str> = text.lines().collect();
    let mut offset = 0;
    for (index, line) in lines.iter().enumerate() {
        if line.trim() == "#[cfg(test)]" {
            let module = lines[index + 1..]
                .iter()
                .find(|next| !next.trim_start().starts_with("#["));
            if module.is_some_and(|next| {
                let next = next.trim_start();
                next.starts_with("mod tests") || next.starts_with("pub(crate) mod tests")
            }) {
                return &text[..offset];
            }
        }
        offset += line.len() + 1;
    }
    text
}

/// Source files compiled only into lib tests; checked below.
const TEST_ONLY_SOURCES: [&str; 5] = [
    "test_relay.rs",
    "fixture_relay.rs",
    "test_fixture.rs",
    "test_link.rs",
    "test_relay_pool.rs",
];

fn production_sources() -> Vec<(String, String)> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut found = Vec::new();
    for directory in [root.clone(), root.join("bin")] {
        for entry in std::fs::read_dir(&directory).unwrap() {
            let path = entry.unwrap().path();
            let name = path.file_name().unwrap().to_str().unwrap().to_owned();
            // Test-only modules (cfg(test) in lib.rs) and test files.
            if !name.ends_with(".rs")
                || name.ends_with("_tests.rs")
                || TEST_ONLY_SOURCES.contains(&name.as_str())
            {
                continue;
            }
            let text = std::fs::read_to_string(&path).unwrap();
            found.push((name, production_part(&text).to_owned()));
        }
    }
    found
}

#[test]
fn test_only_sources_are_declared_only_under_cfg_test() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let lib = std::fs::read_to_string(root.join("lib.rs")).unwrap();
    let relay = std::fs::read_to_string(root.join("test_relay.rs")).unwrap();
    for name in TEST_ONLY_SOURCES {
        let module = name.trim_end_matches(".rs");
        let declared = if module == "test_relay_pool" {
            // A child of the cfg(test) test_relay module.
            relay.contains("#[path = \"test_relay_pool.rs\"]\npub(crate) mod pool;")
                && lib.contains(
                    "#[cfg(all(test, target_os = \"macos\", feature = \"apple\"))]\npub(crate) mod test_relay;",
                )
        } else {
            lib.contains(&format!(
                "#[cfg(all(test, target_os = \"macos\", feature = \"apple\"))]\npub(crate) mod {module};"
            ))
        };
        assert!(declared, "{name} is not a cfg(test) module");
        let anywhere = lib.matches(&format!("mod {module};")).count();
        assert!(anywhere <= 1, "{name} is declared twice");
    }
}

#[test]
fn production_test_module_cut_keeps_production_and_drops_tests() {
    let text =
        "a\n#[cfg(test)]\nfn helper() {}\nb\n#[cfg(test)]\n#[path = \"x.rs\"]\nmod tests;\nc\n";
    assert_eq!(
        production_part(text),
        "a\n#[cfg(test)]\nfn helper() {}\nb\n"
    );
    let inline = "a\n#[cfg(test)]\npub(crate) mod tests {\n}\n";
    assert_eq!(production_part(inline), "a\n");
    assert_eq!(production_part("x\ny\n"), "x\ny\n");
}

#[test]
fn no_production_relay_dial_bypasses_the_bound_socket_helper() {
    let sources = production_sources();
    assert!(sources.len() > 20, "{}", sources.len());
    for (name, text) in &sources {
        for forbidden in [
            "TcpStream::connect",
            "TcpStream::connect_timeout",
            "TcpSocket::new",
            "libc::connect",
        ] {
            // Only the helper itself creates sockets.
            if name == "relay_socket.rs" && forbidden != "TcpStream::connect" {
                continue;
            }
            assert!(!text.contains(forbidden), "{name} contains {forbidden}");
        }
    }
    // Every relay dial site goes through the helper.
    let count = |file: &str, pattern: &str| {
        sources
            .iter()
            .find(|(name, _)| name == file)
            .map_or(0, |(_, text)| text.matches(pattern).count())
    };
    for (file, pattern, expected) in [
        (
            "provider_session_body.rs",
            "relay_socket::connect_bound(",
            1,
        ),
        ("provider_session_body.rs", "opener.connect()", 1),
        ("provider_session_body.rs", "request.connect()", 1),
        // v40: the opener's and the re-ACK request's dials go through one
        // helper that notes a refused dial as the pin's carrier fault.
        ("local_identity.rs", "connect_bound(peer, interface)", 1),
        (
            "local_identity.rs",
            "dial_pin(&self.crypto, self.peer, &self.interface)",
            2,
        ),
        // S16h: every flow is a stream of a pooled connection, which the
        // flow pool dials; the held crypto no longer dials per flow.
        ("flow_pool.rs", "connect_bound(peer, interface)", 1),
        ("prepared_crypto.rs", "connect_bound(", 0),
        (
            "store_scoped_observation.rs",
            "connect_bound(peer, &interface)",
            1,
        ),
        ("relay_socket.rs", "TcpSocket::new_v4()", 1),
        ("relay_socket.rs", "TcpSocket::new_v6()", 1),
    ] {
        assert_eq!(count(file, pattern), expected, "{file}: {pattern}");
    }
}
