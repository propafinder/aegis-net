//! S18 sleep/wake and path changes: pure interface selection, coalescing and
//! the re-pin table, plus real sessions against the loopback test relay. The
//! `Epoch` below performs exactly the provider's main-runloop decisions for
//! a wake (`wake_on_main`), a path change (`path_changed_on_main`) and the
//! S17 loss and rebuild observations, and counts their native effects.
use super::*;
use crate::{
    app_group::CapturedAppGroupInputs,
    bridge::{LeasedPacketBridge, PacketBridge},
    policy::{Effect, Lifecycle},
    provider_session::{SessionHandle, SessionPhase, SessionProbe},
    provider_session_body::{
        next_reack_ns, reack_due_ns, spawn_on_bridge, spawn_pinned,
        tests::{frame, saved, store_locked, wait_until},
        Lease, Trace, REACK_SPACING,
    },
    relay_socket::admit_physical,
    session_rebuild::{
        classify, rebuild_finished, session_lost, Finished, Lost, Rebuild, RebuildFactory,
        Rebuilds, Recovery, Refusal, Schedule,
    },
    test_fixture::ReadyTree,
    test_relay::{AckReply, Behavior, RelayIdentity, TestRelay, ADMISSION_TIMEOUT},
};
use aegis_client::capture_lease_gate::CaptureLeaseDeadline;
use std::{
    net::{Ipv4Addr, Ipv6Addr},
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    thread,
};

const FAST: Schedule = Schedule {
    first: Duration::from_millis(40),
    cap: Duration::from_millis(160),
    construct: Duration::from_secs(5),
    stable: Duration::from_secs(30),
};

fn iface(name: &str, index: u32, kind: InterfaceKind) -> PathInterface {
    PathInterface {
        name: name.into(),
        index,
        kind,
    }
}

fn address(name: &str, address: IpAddr) -> InterfaceAddress {
    InterfaceAddress {
        name: name.into(),
        address,
        up: true,
        loopback: false,
        point_to_point: false,
    }
}

fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(a, b, c, d))
}

fn egress(name: &str, index: u32, addresses: &[IpAddr]) -> Egress {
    Egress {
        name: name.into(),
        index,
        addresses: addresses.to_vec(),
    }
}

/// A satisfied path whose only egress is `name`/`index` holding `addresses`.
fn on(name: &str, index: u32, addresses: &[IpAddr]) -> PathObservation {
    PathObservation {
        usable: vec![egress(name, index, addresses)],
    }
}

/// The primary interface `observe` picks when every listed interface holds
/// one IPv4 address.
fn chosen(satisfied: bool, path: &[PathInterface]) -> Option<String> {
    let addresses: Vec<_> = path
        .iter()
        .enumerate()
        .map(|(n, interface)| address(&interface.name, v4(10, 0, 0, n as u8 + 1)))
        .collect();
    observe(satisfied, path, false, &addresses)
        .primary()
        .map(|egress| egress.name.clone())
}

#[test]
fn path_selection_picks_the_first_satisfied_physical_interface_and_never_a_tunnel() {
    use InterfaceKind::*;
    // Preference order is kept; the tunnel listed first is skipped.
    let path = [
        iface("utun4", 21, Other),
        iface("en7", 7, Wired),
        iface("en0", 11, Wifi),
    ];
    assert_eq!(chosen(true, &path).as_deref(), Some("en7"));
    assert!(chosen(false, &path).is_none());
    // A refused name never passes, whatever type it reports.
    for refused in [
        "utun0", "ipsec0", "lo0", "awdl0", "llw0", "ppp0", "gif0", "",
    ] {
        for kind in [Wifi, Wired, Cellular] {
            let path = [iface(refused, 5, kind), iface("en0", 11, Wifi)];
            assert_eq!(chosen(true, &path).as_deref(), Some("en0"), "{refused}");
            assert!(chosen(true, &path[..1]).is_none(), "{refused}");
        }
    }
    // Only Wi-Fi, wired and cellular types may carry the relay.
    for kind in [Other, Loopback] {
        assert!(chosen(true, &[iface("en9", 9, kind)]).is_none());
    }
    for kind in [Wifi, Wired, Cellular] {
        assert!(chosen(true, &[iface("en9", 9, kind)]).is_some());
    }
    // An unindexed interface is never chosen.
    assert!(chosen(true, &[iface("en9", 0, Wired)]).is_none());
    // A path to utun only is no physical path at all.
    let tunnel = [iface("utun3", 20, Other), iface("utun4", 21, Wired)];
    assert_eq!(
        observe(true, &tunnel, false, &[]),
        PathObservation::default()
    );
    assert_eq!(
        (0..=9).map(InterfaceKind::from_raw).collect::<Vec<_>>(),
        [Other, Wifi, Cellular, Wired, Loopback, Other, Other, Other, Other, Other]
    );
}

#[test]
fn path_observation_keeps_the_primary_relay_family_addresses_only() {
    use InterfaceKind::*;
    let path = [iface("en7", 7, Wired), iface("en0", 11, Wifi)];
    let six = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 7));
    let mut down = address("en7", v4(10, 0, 0, 9));
    down.up = false;
    let addresses = [
        address("en7", v4(192, 168, 1, 50)),
        address("en7", v4(192, 168, 1, 20)),
        address("en7", v4(192, 168, 1, 20)),
        address("en7", v4(169, 254, 3, 3)),
        address("en7", six),
        address(
            "en7",
            IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1)),
        ),
        address("en0", v4(192, 168, 1, 60)),
        down,
    ];
    let observed = observe(true, &path, false, &addresses);
    assert_eq!(
        observed.usable,
        [
            egress("en7", 7, &[v4(192, 168, 1, 20), v4(192, 168, 1, 50)]),
            egress("en0", 11, &[v4(192, 168, 1, 60)]),
        ]
    );
    assert_eq!(observed.primary(), Some(&observed.usable[0]));
    // An IPv6 relay fingerprints the IPv6 addresses, never link-local; en0
    // holds no IPv6 address, so it cannot carry that relay at all.
    let observed = observe(true, &path, true, &addresses);
    assert_eq!(observed.usable, [egress("en7", 7, &[six])]);
    // An unsatisfied path offers nothing.
    assert_eq!(
        observe(false, &path, false, &addresses),
        PathObservation::default()
    );
}

#[test]
fn path_observation_skips_an_interface_without_a_relay_family_address() {
    use InterfaceKind::*;
    // Wi-Fi is first in service order but joined an IPv6-only network (or
    // DHCPv4 failed and it self-assigned 169.254/16): an IPv4 relay must
    // stay on the wired interface that still holds IPv4.
    let path = [iface("en0", 11, Wifi), iface("en7", 7, Wired)];
    let six = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 11));
    let mut down = address("en0", v4(192, 168, 1, 60));
    down.up = false;
    let addresses = [
        address("en0", six),
        address("en0", v4(169, 254, 9, 9)),
        down,
        address("en7", v4(192, 168, 1, 20)),
    ];
    let observed = observe(true, &path, false, &addresses);
    assert_eq!(observed.usable, [egress("en7", 7, &[v4(192, 168, 1, 20)])]);
    assert_eq!(observed.primary().unwrap().name, "en7");
    // The IPv6 relay prefers Wi-Fi, which holds IPv6, and skips en7.
    let observed = observe(true, &path, true, &addresses);
    assert_eq!(observed.usable, [egress("en0", 11, &[six])]);
    // No interface with a relay-family address: no usable path at all.
    let observed = observe(true, &path[..1], false, &addresses);
    assert_eq!(observed, PathObservation::default());
    assert!(observed.primary().is_none());
    // A hand-made observation listing an address-less egress first still
    // never offers it as primary or as the pinned egress.
    let observed = PathObservation {
        usable: vec![egress("en0", 11, &[]), egress("en7", 7, &[v4(10, 0, 0, 7)])],
    };
    assert_eq!(observed.primary().unwrap().name, "en7");
    assert_eq!(
        path_action(
            Some(&RelayInterface::for_test("en0", 11)),
            None,
            false,
            &observed
        ),
        PathAction::Repin(egress("en7", 7, &[v4(10, 0, 0, 7)]))
    );
    let empty = PathObservation {
        usable: vec![egress("en0", 11, &[])],
    };
    assert!(empty.primary().is_none());
    assert_eq!(
        path_action(
            Some(&RelayInterface::for_test("en7", 7)),
            None,
            false,
            &empty
        ),
        PathAction::Ignore
    );
}

#[test]
fn path_burst_is_coalesced_into_its_last_observation() {
    let start = Instant::now();
    let at = |ms: u64| start + Duration::from_millis(ms);
    let mut debounce = Debounce::default();
    assert!(debounce.take_due(at(0)).is_none());
    // Ten updates 40 ms apart, alternating, ending on en0.
    for n in 0..10u64 {
        let observed = if n % 2 == 0 {
            on("en7", 7, &[])
        } else {
            on("en0", 11, &[])
        };
        debounce.observe(observed, at(n * 40));
        assert!(debounce.take_due(at(n * 40 + 10)).is_none());
    }
    // Not due until QUIET after the last update...
    assert!(debounce.take_due(at(360 + 499)).is_none());
    // ...then exactly once, as the last observation.
    assert_eq!(debounce.take_due(at(360 + 500)), Some(on("en0", 11, &[])));
    assert!(debounce.take_due(at(10_000)).is_none());
    // A burst that never goes quiet is still acted on after HOLD.
    let mut debounce = Debounce::default();
    let mut due = Vec::new();
    for n in 0..60u64 {
        debounce.observe(on("en7", 7, &[v4(10, 0, 0, n as u8)]), at(n * 100));
        if let Some(observed) = debounce.take_due(at(n * 100 + 50)) {
            due.push((n, observed));
        }
    }
    // One per HOLD (2 s) of a 6 s burst, never per update.
    assert_eq!(due.len(), 2, "{due:?}");
    assert!(due
        .iter()
        .all(|(n, _)| n * 100 + 50 >= HOLD.as_millis() as u64));
}

#[test]
fn path_action_rebuilds_only_on_a_changed_or_lost_pinned_egress() {
    let en7 = RelayInterface::for_test("en7", 7);
    let wired_egress = egress("en7", 7, &[v4(192, 168, 1, 20)]);
    let wifi_egress = egress("en0", 11, &[v4(192, 168, 1, 60)]);
    let wired = on("en7", 7, &[v4(192, 168, 1, 20)]);
    let wifi = on("en0", 11, &[v4(192, 168, 1, 60)]);
    let baseline = wired_egress.clone();
    // Multi-homed: Wi-Fi is primary while the route-resolved pin is en7.
    let both = PathObservation {
        usable: vec![wifi_egress.clone(), wired_egress.clone()],
    };
    let none = PathObservation::default();
    // Nothing pinned, or no usable physical path: never a re-pin.
    assert_eq!(path_action(None, None, false, &wired), PathAction::Ignore);
    assert_eq!(
        path_action(None, Some(&baseline), false, &wifi),
        PathAction::Ignore
    );
    assert_eq!(
        path_action(Some(&en7), None, false, &none),
        PathAction::Ignore
    );
    assert_eq!(
        path_action(Some(&en7), Some(&baseline), false, &none),
        PathAction::Ignore
    );
    // The first observation with the pin usable is only the baseline, and
    // the baseline is the pinned interface's own egress, even on a
    // multi-homed Mac whose primary differs.
    assert_eq!(
        path_action(Some(&en7), None, false, &wired),
        PathAction::Baseline(wired_egress.clone())
    );
    assert_eq!(
        path_action(Some(&en7), None, false, &both),
        PathAction::Baseline(wired_egress.clone())
    );
    // The pin vanished before the first observation: re-pin at once.
    assert_eq!(
        path_action(Some(&en7), None, false, &wifi),
        PathAction::Repin(wifi_egress.clone())
    );
    // Unchanged pinned egress: nothing, whatever the other interfaces do.
    // Wi-Fi leaving the multi-homed path makes en7 primary: no rebuild.
    // Wi-Fi appearing first, or renewing to another address: no move.
    for unchanged in [
        wired.clone(),
        both.clone(),
        PathObservation {
            usable: vec![
                egress("en0", 11, &[v4(192, 168, 1, 61)]),
                wired_egress.clone(),
            ],
        },
        PathObservation {
            usable: vec![wired_egress.clone(), wifi_egress.clone()],
        },
    ] {
        assert_eq!(
            path_action(Some(&en7), Some(&baseline), false, &unchanged),
            PathAction::Ignore,
            "{unchanged:?}"
        );
    }
    // The pinned interface's own addresses changed: rebuild on it.
    for (changed, now) in [
        (
            on("en7", 7, &[v4(192, 168, 1, 21)]),
            vec![v4(192, 168, 1, 21)],
        ),
        (
            on("en7", 7, &[v4(192, 168, 1, 20), v4(192, 168, 1, 22)]),
            vec![v4(192, 168, 1, 20), v4(192, 168, 1, 22)],
        ),
        (
            PathObservation {
                usable: vec![wifi_egress.clone(), egress("en7", 7, &[v4(10, 1, 1, 1)])],
            },
            vec![v4(10, 1, 1, 1)],
        ),
    ] {
        assert_eq!(
            path_action(Some(&en7), Some(&baseline), false, &changed),
            PathAction::Repin(egress("en7", 7, &now)),
            "{changed:?}"
        );
    }
    // The pinned interface left the path, came back under a new index, or
    // lost its last relay-family address: re-pin to the preferred usable
    // egress.
    for (lost, target) in [
        (wifi.clone(), wifi_egress.clone()),
        (
            on("en7", 8, &[v4(192, 168, 1, 20)]),
            egress("en7", 8, &[v4(192, 168, 1, 20)]),
        ),
        (
            PathObservation {
                usable: vec![egress("en7", 7, &[]), wifi_egress.clone()],
            },
            wifi_egress.clone(),
        ),
    ] {
        assert_eq!(
            path_action(Some(&en7), Some(&baseline), false, &lost),
            PathAction::Repin(target),
            "{lost:?}"
        );
    }
    // The pinned interface is gone and nothing usable replaces it: keep the
    // pin and fail closed.
    assert_eq!(
        path_action(Some(&en7), Some(&baseline), false, &on("en0", 11, &[])),
        PathAction::Ignore
    );
    // A pinned name whose index changed is not present either.
    let stale = RelayInterface::for_test("en7", 9);
    assert_eq!(
        path_action(Some(&stale), Some(&baseline), false, &wired),
        PathAction::Repin(wired_egress.clone())
    );
    // A baseline that is not the pinned egress never hides a change.
    let pinned_en0 = RelayInterface::for_test("en0", 11);
    assert_eq!(
        path_action(Some(&pinned_en0), Some(&baseline), false, &both),
        PathAction::Repin(wifi_egress)
    );
}

#[test]
fn path_action_moves_a_pin_that_follows_the_primary_to_a_new_primary() {
    // v33 (window-v32-ifswitch-r3): the epoch pinned Wi-Fi en0 while it was
    // the path's primary; a cable plugged into en7 then made en7 primary.
    let en0 = RelayInterface::for_test("en0", 11);
    let wifi_egress = egress("en0", 11, &[v4(192, 168, 1, 168)]);
    let renewed = egress("en0", 11, &[v4(192, 168, 1, 169)]);
    let wired_egress = egress("en7", 7, &[v4(192, 168, 1, 107)]);
    let baseline = wifi_egress.clone();
    let path = |usable: &[&Egress]| PathObservation {
        usable: usable.iter().map(|egress| (*egress).clone()).collect(),
    };
    let plugged = path(&[&wired_egress, &wifi_egress]);
    // A pin that follows the primary moves to the new primary, also when
    // its own addresses changed at the same time.
    for (observed, target) in [
        (plugged.clone(), wired_egress.clone()),
        (path(&[&wired_egress, &renewed]), wired_egress.clone()),
    ] {
        assert_eq!(
            path_action(Some(&en0), Some(&baseline), true, &observed),
            PathAction::Repin(target),
            "{observed:?}"
        );
    }
    // Still the primary: nothing, or its own address change on itself.
    for (observed, action) in [
        (path(&[&wifi_egress]), PathAction::Ignore),
        (path(&[&wifi_egress, &wired_egress]), PathAction::Ignore),
        (path(&[&renewed]), PathAction::Repin(renewed.clone())),
        (
            path(&[&renewed, &wired_egress]),
            PathAction::Repin(renewed.clone()),
        ),
    ] {
        assert_eq!(
            path_action(Some(&en0), Some(&baseline), true, &observed),
            action,
            "{observed:?}"
        );
    }
    // The same name under another index is another interface.
    let reindexed = egress("en0", 12, &[v4(192, 168, 1, 168)]);
    assert_eq!(
        path_action(
            Some(&en0),
            Some(&baseline),
            true,
            &path(&[&reindexed, &wifi_egress])
        ),
        PathAction::Repin(reindexed)
    );
    // An address-less egress listed first is never the new primary.
    let addressless = PathObservation {
        usable: vec![egress("en7", 7, &[]), wifi_egress.clone()],
    };
    assert_eq!(
        path_action(Some(&en0), Some(&baseline), true, &addressless),
        PathAction::Ignore
    );
    // Lost, nothing usable, nothing pinned, no baseline yet: as before.
    assert_eq!(
        path_action(Some(&en0), Some(&baseline), true, &path(&[&wired_egress])),
        PathAction::Repin(wired_egress.clone())
    );
    assert_eq!(
        path_action(
            Some(&en0),
            Some(&baseline),
            true,
            &PathObservation::default()
        ),
        PathAction::Ignore
    );
    assert_eq!(
        path_action(None, Some(&baseline), true, &plugged),
        PathAction::Ignore
    );
    assert_eq!(
        path_action(Some(&en0), None, true, &plugged),
        PathAction::Baseline(wifi_egress.clone())
    );
    // A pin that does not follow the primary stays where it works.
    assert_eq!(
        path_action(Some(&en0), Some(&baseline), false, &plugged),
        PathAction::Ignore
    );
    assert_eq!(
        path_action(
            Some(&en0),
            Some(&baseline),
            false,
            &path(&[&wired_egress, &renewed])
        ),
        PathAction::Repin(renewed)
    );
}

#[test]
fn path_and_wake_effects_follow_the_epoch_phase() {
    for phase in [
        Phase::Idle,
        Phase::Admitted,
        Phase::Applying,
        Phase::Running,
        Phase::Reasserting,
        Phase::Blocking,
        Phase::Stopped,
    ] {
        let (repin, live, lapsed) = match phase {
            Phase::Running => (RepinEffect::Rebuild, WakeAction::Reack, WakeAction::Rebuild),
            Phase::Reasserting => (
                RepinEffect::NextAttempt,
                WakeAction::Reasserting,
                WakeAction::Reasserting,
            ),
            _ => (RepinEffect::Ignore, WakeAction::Ignore, WakeAction::Ignore),
        };
        assert_eq!(repin_effect(phase), repin, "{phase:?}");
        assert_eq!(wake_action(phase, true), live, "{phase:?}");
        assert_eq!(wake_action(phase, false), lapsed, "{phase:?}");
    }
    assert_eq!(
        [
            WakeAction::Reack,
            WakeAction::Rebuild,
            WakeAction::Reasserting,
            WakeAction::Ignore
        ]
        .map(WakeAction::code),
        ["reack", "rebuild", "reasserting", "idle"]
    );
    // The seal a re-pin uses is recoverable: it never cancels the tunnel.
    assert_eq!(classify("relay_path_changed"), Recovery::Recoverable);
}

#[test]
fn path_admission_checks_the_name_and_the_kernel_index() {
    let seven = |name: &str| (name == "en7").then_some(7);
    let admitted = admit_physical("en7", 7, seven).unwrap();
    assert_eq!((admitted.name(), admitted.index()), ("en7", 7));
    // Index 0 would clear IP_BOUND_IF; a stale index names another link.
    assert!(admit_physical("en7", 0, |_| Some(0)).is_err());
    assert!(admit_physical("en7", 8, seven).is_err());
    assert!(admit_physical("en7", 7, |_| None).is_err());
    for refused in ["utun4", "ipsec0", "lo0", "awdl0", "llw0", ""] {
        assert!(
            admit_physical(refused, 7, |_| Some(7)).is_err(),
            "{refused}"
        );
    }
    // The production lookup refuses loopback by name and unknown names.
    let lo0 = RelayInterface::loopback_for_test();
    assert!(RelayInterface::physical("lo0", lo0.index()).is_err());
    assert!(RelayInterface::physical("en-no-such-if", 1).is_err());
}

#[test]
fn path_watch_repins_once_per_coalesced_change_and_ignores_tunnel_paths() {
    let pins = EpochPins::pinned_for_test(RelayInterface::for_test("en7", 7));
    let mut watch = Watch::default();
    let start = Instant::now();
    let at = |ms: u64| start + Duration::from_millis(ms);
    let sink = watch.sink();
    let admitted = std::cell::Cell::new(0);
    let poll = |watch: &mut Watch, now| {
        watch.poll(now, &pins, |name: &str, index| {
            admitted.set(admitted.get() + 1);
            admit_physical(name, index, |_| Some(index))
        })
    };
    // The first observation is the baseline.
    Watch::feed(&sink, on("en7", 7, &[v4(192, 168, 1, 20)]), at(0));
    assert!(!poll(&mut watch, at(100)));
    assert!(!poll(&mut watch, at(500)));
    assert_eq!(admitted.get(), 0);
    // A burst ending on Wi-Fi: one re-pin, after it went quiet.
    for n in 0..8u64 {
        let observed = if n % 2 == 0 {
            on("en0", 11, &[v4(192, 168, 1, 60)])
        } else {
            on("en7", 7, &[v4(192, 168, 1, 20)])
        };
        Watch::feed(&sink, observed, at(1_000 + n * 30));
        assert!(!poll(&mut watch, at(1_000 + n * 30 + 5)));
    }
    Watch::feed(&sink, on("en0", 11, &[v4(192, 168, 1, 60)]), at(1_300));
    assert!(!poll(&mut watch, at(1_799)));
    assert!(poll(&mut watch, at(1_800)));
    assert_eq!(admitted.get(), 1);
    assert_eq!(pins.get(), Some(RelayInterface::for_test("en0", 11)));
    // The same path again, a path to utun only, or none: nothing.
    for (n, observed) in [
        on("en0", 11, &[v4(192, 168, 1, 60)]),
        observe(
            true,
            &[iface("utun4", 21, InterfaceKind::Other)],
            false,
            &[],
        ),
        PathObservation::default(),
    ]
    .into_iter()
    .enumerate()
    {
        let t = 3_000 + n as u64 * 1_000;
        Watch::feed(&sink, observed, at(t));
        assert!(!poll(&mut watch, at(t + 600)));
    }
    assert_eq!(admitted.get(), 1);
    assert_eq!(pins.get(), Some(RelayInterface::for_test("en0", 11)));
    // A refused admission leaves the pin and rebuilds nothing.
    Watch::feed(&sink, on("en5", 5, &[v4(10, 0, 0, 5)]), at(7_000));
    assert!(!watch.poll(at(7_600), &pins, |_, _| Err("relay_interface_unresolved")));
    assert_eq!(pins.get(), Some(RelayInterface::for_test("en0", 11)));
}

#[test]
fn path_watch_keeps_a_working_multi_homed_pin_through_other_interface_changes() {
    // The first session's route lookup pinned wired en7 while Wi-Fi en0 is
    // the path's primary.
    let pins = EpochPins::pinned_for_test(RelayInterface::for_test("en7", 7));
    let mut watch = Watch::default();
    let start = Instant::now();
    let at = |ms: u64| start + Duration::from_millis(ms);
    let sink = watch.sink();
    let admitted = std::cell::RefCell::new(Vec::new());
    let poll = |watch: &mut Watch, now| {
        watch.poll(now, &pins, |name: &str, index| {
            admitted.borrow_mut().push((name.to_string(), index));
            admit_physical(name, index, |_| Some(index))
        })
    };
    let wired = egress("en7", 7, &[v4(192, 168, 1, 20)]);
    let both = |wifi: IpAddr| PathObservation {
        usable: vec![egress("en0", 11, &[wifi]), wired.clone()],
    };
    Watch::feed(&sink, both(v4(192, 168, 1, 60)), at(0));
    assert!(!poll(&mut watch, at(600)));
    // Wi-Fi renews to another address, drops, returns: never a rebuild.
    for (n, observed) in [
        both(v4(192, 168, 1, 61)),
        PathObservation {
            usable: vec![wired.clone()],
        },
        both(v4(192, 168, 1, 62)),
    ]
    .into_iter()
    .enumerate()
    {
        let t = 1_000 + n as u64 * 1_000;
        Watch::feed(&sink, observed, at(t));
        assert!(!poll(&mut watch, at(t + 600)), "{n}");
    }
    assert!(admitted.borrow().is_empty());
    assert_eq!(pins.get(), Some(RelayInterface::for_test("en7", 7)));
    // Wi-Fi leaves first in order: still the same working pin.
    Watch::feed(
        &sink,
        PathObservation {
            usable: vec![wired.clone(), egress("en0", 11, &[v4(192, 168, 1, 62)])],
        },
        at(5_000),
    );
    assert!(!poll(&mut watch, at(5_600)));
    assert!(admitted.borrow().is_empty());
    // en7 renews to a new address: exactly one rebuild, on en7 itself.
    let renewed = egress("en7", 7, &[v4(192, 168, 1, 21)]);
    Watch::feed(
        &sink,
        PathObservation {
            usable: vec![egress("en0", 11, &[v4(192, 168, 1, 62)]), renewed.clone()],
        },
        at(7_000),
    );
    assert!(poll(&mut watch, at(7_600)));
    assert_eq!(*admitted.borrow(), [("en7".to_string(), 7)]);
    assert_eq!(pins.get(), Some(RelayInterface::for_test("en7", 7)));
    // v33: re-pinned behind the primary, it still does not follow it.
    Watch::feed(
        &sink,
        PathObservation {
            usable: vec![egress("en0", 11, &[v4(192, 168, 1, 62)]), renewed.clone()],
        },
        at(8_000),
    );
    assert!(!poll(&mut watch, at(8_600)));
    Watch::feed(
        &sink,
        PathObservation {
            usable: vec![renewed.clone()],
        },
        at(9_000),
    );
    assert!(!poll(&mut watch, at(9_600)));
    // en7 is unplugged: re-pin to Wi-Fi.
    Watch::feed(&sink, on("en0", 11, &[v4(192, 168, 1, 62)]), at(11_000));
    assert!(poll(&mut watch, at(11_600)));
    assert_eq!(pins.get(), Some(RelayInterface::for_test("en0", 11)));
    assert_eq!(admitted.borrow().len(), 2);
    // v33: re-pinned on the primary, the pin now follows it: the cable
    // plugged in again makes en7 primary and moves the pin there.
    Watch::feed(
        &sink,
        PathObservation {
            usable: vec![renewed, egress("en0", 11, &[v4(192, 168, 1, 62)])],
        },
        at(13_000),
    );
    assert!(poll(&mut watch, at(13_600)));
    assert_eq!(pins.get(), Some(RelayInterface::for_test("en7", 7)));
    assert_eq!(admitted.borrow().len(), 3);
}

#[test]
fn path_watch_moves_a_pin_taken_on_the_primary_to_a_new_primary_once() {
    // v33, the plug of window-v32-ifswitch-r3 replayed: Wi-Fi en0 is the
    // only (so primary) egress when the epoch's pin is taken, then a cable
    // in en7 makes en7 primary while en0 keeps its address.
    let pins = EpochPins::pinned_for_test(RelayInterface::for_test("en0", 11));
    let mut watch = Watch::default();
    let start = Instant::now();
    let at = |ms: u64| start + Duration::from_millis(ms);
    let sink = watch.sink();
    let admitted = std::cell::RefCell::new(Vec::new());
    let refuse = std::cell::Cell::new(false);
    let poll = |watch: &mut Watch, now| {
        watch.poll(now, &pins, |name: &str, index| {
            admitted.borrow_mut().push((name.to_string(), index));
            if refuse.get() {
                return Err("relay_interface_unresolved");
            }
            admit_physical(name, index, |_| Some(index))
        })
    };
    let wifi = egress("en0", 11, &[v4(192, 168, 1, 168)]);
    let wired = egress("en7", 7, &[v4(192, 168, 1, 107)]);
    let path = |usable: &[&Egress]| PathObservation {
        usable: usable.iter().map(|egress| (*egress).clone()).collect(),
    };
    Watch::feed(&sink, path(&[&wifi]), at(0));
    assert!(!poll(&mut watch, at(600)));
    assert!(admitted.borrow().is_empty());
    // The plug: exactly one re-pin, to en7, once the burst went quiet.
    Watch::feed(&sink, path(&[&wifi]), at(1_000));
    Watch::feed(&sink, path(&[&wired, &wifi]), at(1_100));
    assert!(!poll(&mut watch, at(1_599)));
    assert!(poll(&mut watch, at(1_600)));
    assert_eq!(*admitted.borrow(), [("en7".to_string(), 7)]);
    assert_eq!(pins.get(), Some(RelayInterface::for_test("en7", 7)));
    // The same path again, or en0 renewing behind en7: nothing.
    for (n, observed) in [
        path(&[&wired, &wifi]),
        path(&[&wired, &egress("en0", 11, &[v4(192, 168, 1, 169)])]),
    ]
    .into_iter()
    .enumerate()
    {
        let t = 3_000 + n as u64 * 1_000;
        Watch::feed(&sink, observed, at(t));
        assert!(!poll(&mut watch, at(t + 600)), "{n}");
    }
    assert_eq!(admitted.borrow().len(), 1);
    // The unplug: en7 lost, back to Wi-Fi (the S18 rule, now on a pin that
    // names the interface the relay really uses).
    let back = egress("en0", 11, &[v4(192, 168, 1, 169)]);
    Watch::feed(&sink, path(&[&back]), at(6_000));
    assert!(poll(&mut watch, at(6_600)));
    assert_eq!(pins.get(), Some(RelayInterface::for_test("en0", 11)));
    // A refused admission of a new primary keeps the pin and is tried
    // again at the next update.
    refuse.set(true);
    Watch::feed(&sink, path(&[&wired, &back]), at(8_000));
    assert!(!poll(&mut watch, at(8_600)));
    assert_eq!(pins.get(), Some(RelayInterface::for_test("en0", 11)));
    refuse.set(false);
    Watch::feed(&sink, path(&[&wired, &back]), at(9_000));
    assert!(poll(&mut watch, at(9_600)));
    assert_eq!(pins.get(), Some(RelayInterface::for_test("en7", 7)));
    assert_eq!(
        *admitted.borrow(),
        [
            ("en7".to_string(), 7),
            ("en0".to_string(), 11),
            ("en7".to_string(), 7),
            ("en7".to_string(), 7)
        ]
    );
}

#[test]
fn reack_forced_is_due_after_the_spacing_and_never_sooner() {
    let ms = 1_000_000u64;
    let spacing = REACK_SPACING.as_nanos() as u64;
    let lease = Lease {
        deadline_ns: 10_000 * ms,
        last_attempt_ns: 1_000 * ms,
        lead: Duration::from_secs(2),
    };
    assert_eq!(
        reack_due_ns(lease, false, REACK_SPACING),
        next_reack_ns(lease)
    );
    assert_eq!(
        reack_due_ns(lease, true, REACK_SPACING),
        1_000 * ms + spacing
    );
    assert!(reack_due_ns(lease, true, REACK_SPACING) < reack_due_ns(lease, false, REACK_SPACING));
    for last in [0, 1, 7 * ms, u64::MAX - spacing, u64::MAX] {
        let lease = Lease {
            last_attempt_ns: last,
            ..lease
        };
        assert!(reack_due_ns(lease, true, REACK_SPACING) >= last.saturating_add(spacing));
    }
}

#[test]
fn reack_requests_coalesce_until_one_attempt_takes_them() {
    let bridge = LeasedPacketBridge::new(PacketBridge::default(), CaptureLeaseDeadline::default());
    let mut session = SessionHandle::spawn(
        bridge,
        |_| {},
        |control| {
            while !control.stop_requested() {
                thread::park_timeout(Duration::from_millis(5));
            }
            Ok(())
        },
    )
    .unwrap();
    let probe = session.probe();
    assert!(!probe.reack_requested());
    assert!(!probe.take_reack());
    probe.request_reack();
    probe.request_reack();
    assert!(probe.reack_requested());
    assert!(probe.take_reack());
    assert!(!probe.take_reack());
    assert!(!probe.reack_requested());
    assert!(session.try_join(Duration::from_secs(2)));
}

#[test]
fn path_monitor_reports_an_initial_path_and_cancels() {
    // Read-only: a Network.framework path monitor binds nothing.
    let watch = Watch::default();
    let monitor = PathMonitor::start(watch.sink(), false).expect("path monitor");
    let sink = watch.sink();
    let reported = wait_until(Duration::from_secs(5), || {
        sink.lock().unwrap().pending.is_some()
    });
    assert!(reported.is_some(), "no initial path update");
    let (observed, _, _) = sink.lock().unwrap().pending.clone().unwrap();
    // Whatever this Mac's path is, it never names a tunnel or loopback.
    // Every usable egress holds an address of the relay's family.
    for egress in &observed.usable {
        assert!(!relay_socket::refused_name(&egress.name), "{}", egress.name);
        assert_ne!(egress.index, 0);
        assert!(!egress.addresses.is_empty(), "{}", egress.name);
        assert!(egress.addresses.iter().all(IpAddr::is_ipv4));
    }
    if let Some(primary) = observed.primary() {
        assert!(!relay_socket::refused_name(&primary.name));
    }
    drop(monitor);
    assert!(sink
        .lock()
        .unwrap()
        .take_due(Instant::now() + HOLD)
        .is_some());
}

fn server_ack(tree: &ReadyTree) -> Behavior {
    Behavior::AckThenClose {
        reply: AckReply::for_tree(tree),
        idle: ADMISSION_TIMEOUT,
    }
}

/// Connection 0 is always served; later ones only while `accepting`.
fn gated_relay(accepting: Arc<AtomicBool>) -> (TestRelay, Arc<ReadyTree>) {
    let listener = TestRelay::bind();
    let tree = Arc::new(ReadyTree::with_online_completed(
        listener.local_addr().unwrap(),
    ));
    let served = tree.clone();
    let relay = TestRelay::spawn_each(listener, RelayIdentity::for_tree(&tree), move |index| {
        (index == 0 || accepting.load(Ordering::SeqCst)).then(|| server_ack(&served))
    });
    (relay, tree)
}

/// The production rebuild factory over the unsigned test claim: rebuilt
/// sessions bind to whatever the epoch has pinned, never resolving.
fn factory(tree: Arc<ReadyTree>, pinned: EpochPins, trace: Option<Trace>) -> RebuildFactory {
    Box::new(move |notifier, _stop| {
        let claim = CapturedAppGroupInputs::capture_test_root(tree.root())
            .map_err(|error| Refusal::custody(&error))?;
        spawn_pinned(
            saved(&tree),
            claim,
            notifier,
            trace.clone(),
            pinned.clone(),
            None,
        )
        .map_err(|_| Refusal::transient("session_spawn_failed"))
    })
}

type Steps = Arc<Mutex<Vec<(&'static str, Instant)>>>;

fn recorder() -> (Trace, Steps) {
    let steps: Steps = Arc::default();
    let held = steps.clone();
    let trace: Trace = Arc::new(move |step| held.lock().unwrap().push((step, Instant::now())));
    (trace, steps)
}

fn count(steps: &Steps, wanted: &str) -> usize {
    steps
        .lock()
        .unwrap()
        .iter()
        .filter(|(step, _)| *step == wanted)
        .count()
}

/// The provider's main-runloop decisions over real sessions.
struct Epoch {
    tree: Arc<ReadyTree>,
    pinned: EpochPins,
    lifecycle: Lifecycle,
    g: u64,
    session: Arc<Mutex<SessionHandle>>,
    probe: SessionProbe,
    rebuilds: Rebuilds,
    watch: Watch,
    applied: usize,
    cancels: usize,
    reassertions: usize,
    swaps: usize,
    reacks: usize,
    // Traces every rebuilt session; the attempts of the last swap.
    rebuild_trace: Option<Trace>,
    swapped_attempts: u32,
}

impl Epoch {
    fn start(tree: Arc<ReadyTree>, trace: Option<Trace>) -> Self {
        let mut lifecycle = Lifecycle::default();
        let g = lifecycle.admit().unwrap();
        let pinned = EpochPins::default();
        let claim = CapturedAppGroupInputs::capture_test_root(tree.root()).unwrap();
        let (tx, rx) = mpsc::channel();
        let session = spawn_pinned(
            saved(&tree),
            claim,
            move |phase| {
                let _ = tx.send(phase);
            },
            trace,
            pinned.clone(),
            Some(RelayInterface::loopback_for_test()),
        )
        .unwrap();
        assert_eq!(
            rx.recv_timeout(Duration::from_secs(3)).ok(),
            Some(SessionPhase::Ready),
            "{:?}",
            session.refusal()
        );
        let probe = session.probe();
        let mut applied = 0;
        if lifecycle.session_ready(g) == Effect::ApplySettings {
            applied += 1;
        }
        assert_eq!(lifecycle.ready(g), Ok(Effect::CompleteStart));
        Self {
            tree,
            pinned,
            lifecycle,
            g,
            session: Arc::new(Mutex::new(session)),
            probe,
            rebuilds: Rebuilds::default(),
            watch: Watch::default(),
            applied,
            cancels: 0,
            reassertions: 0,
            swaps: 0,
            reacks: 0,
            rebuild_trace: None,
            swapped_attempts: 0,
        }
    }

    /// session_lost_on_main.
    fn lost(&mut self) {
        let (phase, refusal) = self.probe.phase_reader().snapshot();
        if phase == SessionPhase::Ready && self.probe.ready() {
            return;
        }
        match session_lost(
            &mut self.lifecycle,
            self.g,
            refusal.unwrap_or("packet_path_not_ready"),
        ) {
            Lost::Reassert => {
                let lost = self.session.clone();
                let factory = factory(
                    self.tree.clone(),
                    self.pinned.clone(),
                    self.rebuild_trace.clone(),
                );
                self.rebuilds
                    .start_with(FAST, Instant::now(), move |spent| {
                        Rebuild::spawn(lost, factory, FAST, None, Box::new(|| {}), spent)
                    })
                    .unwrap();
                self.reassertions += 1;
            }
            Lost::Fail(_) => {
                if self.lifecycle.fail(self.g).is_ok() {
                    self.cancels += 1;
                }
            }
            Lost::Ignore => {}
        }
    }

    /// wake_on_main.
    fn wake(&mut self) -> WakeAction {
        let action = wake_action(self.lifecycle.phase, self.probe.ready());
        match action {
            WakeAction::Reack => {
                self.probe.request_reack();
                self.reacks += 1;
            }
            WakeAction::Rebuild => self.lost(),
            WakeAction::Reasserting | WakeAction::Ignore => {}
        }
        action
    }

    /// path_changed_on_main at `now`. The loopback relay is reachable only
    /// over lo0, so the test's other "physical" interface carries lo0's
    /// index (a bound socket follows the index alone) under its own name.
    fn path(&mut self, now: Instant) -> bool {
        let lo0 = RelayInterface::loopback_for_test().index();
        let repinned = self.watch.poll(now, &self.pinned, |name, index| {
            admit_physical(name, index, |_| Some(lo0))
        });
        if repinned && repin_effect(self.lifecycle.phase) == RepinEffect::Rebuild {
            self.probe.seal("relay_path_changed");
            self.lost();
        }
        repinned
    }

    /// One drain-timer observation: loss, then a finished rebuild.
    fn tick(&mut self) {
        if self.lifecycle.phase == Phase::Running && !self.probe.ready() {
            self.lost();
        }
        let Some(rebuild) = self.rebuilds.current.clone() else {
            return;
        };
        let finished = rebuild_finished(&mut self.lifecycle, self.g, &mut rebuild.lock().unwrap());
        match finished {
            Finished::Swap(session, attempts) => {
                self.rebuilds.swapped(attempts, Instant::now());
                self.swapped_attempts = attempts;
                self.probe = session.probe();
                self.session = Arc::new(Mutex::new(session));
                self.swaps += 1;
            }
            Finished::Fail(_) => {
                if self.lifecycle.fail(self.g).is_ok() {
                    self.cancels += 1;
                }
            }
            Finished::Ignore => {}
        }
    }

    fn tick_until(&mut self, budget: Duration, mut done: impl FnMut(&Self) -> bool) -> bool {
        let deadline = Instant::now() + budget;
        loop {
            self.tick();
            if done(self) {
                return true;
            }
            if Instant::now() >= deadline {
                return false;
            }
            thread::sleep(Duration::from_millis(2));
        }
    }

    fn stop(&mut self) -> bool {
        let started = Instant::now();
        let (g, _) = self.lifecycle.stop().unwrap();
        loop {
            let rebuilt =
                self.rebuilds.current.as_ref().is_none_or(|rebuild| {
                    rebuild.lock().unwrap().seal_and_try_join(Duration::ZERO)
                });
            let joined = self.session.lock().unwrap().try_join(Duration::ZERO);
            if rebuilt && joined {
                return self.lifecycle.joined(g) == Effect::CompleteStop;
            }
            if started.elapsed() > Duration::from_secs(2) {
                return false;
            }
            thread::sleep(Duration::from_millis(20));
        }
    }
}

#[test]
fn wake_with_a_live_lease_forces_exactly_one_reack() {
    let (_relay, tree) = gated_relay(Arc::new(AtomicBool::new(true)));
    let (trace, steps) = recorder();
    // A test-held bridge clock: the lease schedule never comes due on its
    // own, so every attempt below is the wake's.
    let clock = Arc::new(std::sync::atomic::AtomicU64::new(10_000_000_000));
    let now = clock.clone();
    let bridge = LeasedPacketBridge::with_clock(
        PacketBridge::default(),
        CaptureLeaseDeadline::default(),
        move || Ok(now.load(Ordering::SeqCst)),
    );
    let claim = CapturedAppGroupInputs::capture_test_root(tree.root()).unwrap();
    let (tx, rx) = mpsc::channel();
    let mut session = spawn_on_bridge(
        saved(&tree),
        claim,
        move |phase| {
            let _ = tx.send(phase);
        },
        Some(trace),
        bridge,
    )
    .unwrap();
    assert_eq!(
        rx.recv_timeout(Duration::from_secs(3)).ok(),
        Some(SessionPhase::Ready),
        "{:?}",
        session.refusal()
    );
    let probe = session.probe();
    thread::sleep(Duration::from_millis(300));
    assert_eq!(count(&steps, "reack_attempt"), 0);
    // Wake with the lease live: one re-ACK is requested...
    let action = wake_action(Phase::Running, probe.ready());
    assert_eq!(action, WakeAction::Reack);
    probe.request_reack();
    // ...and never sooner than the spacing after the last attempt.
    thread::sleep(Duration::from_millis(300));
    assert_eq!(count(&steps, "reack_attempt"), 0);
    let spacing = REACK_SPACING.as_nanos() as u64;
    clock.fetch_add(spacing + 100_000_000, Ordering::SeqCst);
    // One forced attempt, which renews the lease, well before the lease
    // schedule (lead before the 2.75 s lease end) is due.
    assert!(
        wait_until(Duration::from_secs(3), || count(&steps, "reack_renewed")
            == 1)
        .is_some()
    );
    assert_eq!(count(&steps, "reack_forced"), 1);
    assert_eq!(count(&steps, "reack_attempt"), 1);
    // The one wake never forces a second, even once the spacing after the
    // forced attempt has passed (the renewed lease is not yet due).
    thread::sleep(Duration::from_millis(500));
    clock.fetch_add(spacing + 50_000_000, Ordering::SeqCst);
    thread::sleep(Duration::from_millis(700));
    assert_eq!(count(&steps, "reack_attempt"), 1);
    assert_eq!(count(&steps, "reack_forced"), 1);
    assert!(probe.ready());
    assert!(session.try_join(Duration::from_secs(2)));
    assert!(!store_locked(&tree.identity_dir()));
}

#[test]
fn wake_after_the_lease_lapsed_enters_exactly_one_rebuild() {
    let accepting = Arc::new(AtomicBool::new(false));
    let (_relay, tree) = gated_relay(accepting.clone());
    let mut epoch = Epoch::start(tree.clone(), None);
    // Asleep: no re-ACK reaches the relay and the lease runs out on the
    // bridge clock, which keeps counting through sleep.
    assert!(wait_until(Duration::from_secs(8), || epoch
        .probe
        .bridge()
        .lease_elapsed())
    .is_some());
    assert_eq!(epoch.lifecycle.phase, Phase::Running);
    assert_eq!(epoch.wake(), WakeAction::Rebuild);
    assert_eq!(epoch.lifecycle.phase, Phase::Reasserting);
    assert_eq!(
        epoch.probe.phase_reader().snapshot().1,
        Some("capture_lease_expired")
    );
    // A repeated wake while reasserting starts nothing more, and says so.
    assert_eq!(epoch.wake(), WakeAction::Reasserting);
    assert_eq!((epoch.reassertions, epoch.reacks), (1, 0));
    // The relay returns: the rebuilt session takes over without a second
    // settings application or any cancel.
    accepting.store(true, Ordering::SeqCst);
    assert!(epoch.tick_until(Duration::from_secs(5), |e| e.swaps == 1));
    assert_eq!(epoch.lifecycle.phase, Phase::Running);
    assert!(epoch.probe.ready());
    epoch.probe.bridge().from_os(&frame()).unwrap();
    assert_eq!(
        (
            epoch.applied,
            epoch.reassertions,
            epoch.cancels,
            epoch.swaps
        ),
        (1, 1, 0, 1)
    );
    assert!(epoch.stop());
    assert!(!store_locked(&tree.identity_dir()));
}

/// S20b: before its first dial a session records, in the epoch pins, the
/// exact relay endpoint and the held profile's enrollment authority that
/// the leak guard allows once the settings may be applied.
#[test]
fn a_session_records_its_relay_and_authority_endpoints_for_the_leak_guard() {
    let (_relay, tree) = gated_relay(Arc::new(AtomicBool::new(true)));
    let mut epoch = Epoch::start(tree.clone(), None);
    assert_eq!(
        epoch.pinned.guard(),
        Some(crate::provider_session_body::GuardEndpoints::one(
            tree.relay(),
            Some("127.0.0.1:8443".parse().unwrap()),
        ))
    );
    assert!(epoch.stop());
    assert!(!store_locked(&tree.identity_dir()));
}

#[test]
fn path_change_to_another_physical_interface_repins_and_rebuilds_exactly_once() {
    let (relay, tree) = gated_relay(Arc::new(AtomicBool::new(true)));
    let mut epoch = Epoch::start(tree.clone(), None);
    let lo0 = RelayInterface::loopback_for_test();
    let first = epoch.probe.clone();
    let sink = epoch.watch.sink();
    let start = Instant::now();
    let at = |ms: u64| start + Duration::from_millis(ms);
    // Baseline: the pinned interface, behind another primary interface.
    let pinned = egress("lo0", lo0.index(), &[v4(127, 0, 0, 1)]);
    let multi = PathObservation {
        usable: vec![egress("en0", 11, &[v4(192, 168, 1, 60)]), pinned.clone()],
    };
    Watch::feed(&sink, multi, at(0));
    assert!(!epoch.path(at(600)));
    // The other interface leaves: the pinned one becomes primary, but the
    // working session is neither sealed nor rebuilt.
    Watch::feed(
        &sink,
        PathObservation {
            usable: vec![pinned],
        },
        at(700),
    );
    assert!(!epoch.path(at(1_300)));
    assert_eq!(epoch.reassertions, 0);
    assert!(epoch.probe.ready());
    // A burst of updates ending on another physical interface: acted on
    // once, after it went quiet.
    for n in 0..6u64 {
        Watch::feed(
            &sink,
            on("en7", 7, &[v4(192, 168, 1, 20)]),
            at(2_000 + n * 50),
        );
        assert!(!epoch.path(at(2_000 + n * 50 + 10)));
    }
    let wifi = on("en0", lo0.index(), &[v4(192, 168, 1, 60)]);
    Watch::feed(&sink, wifi.clone(), at(2_400));
    assert!(!epoch.path(at(2_899)));
    assert!(epoch.path(at(2_900)));
    assert_eq!(epoch.reassertions, 1);
    assert_eq!(epoch.lifecycle.phase, Phase::Reasserting);
    assert_eq!(
        first.phase_reader().snapshot().1,
        Some("relay_path_changed")
    );
    // The same path again: no second re-pin or rebuild.
    assert_eq!(
        epoch.pinned.get(),
        Some(RelayInterface::for_test("en0", lo0.index()))
    );
    Watch::feed(&sink, wifi, at(3_000));
    assert!(!epoch.path(at(3_600)));
    // A path to utun only is ignored, even while reasserting.
    let tunnel = observe(
        true,
        &[iface("utun4", 21, InterfaceKind::Other)],
        false,
        &[],
    );
    Watch::feed(&sink, tunnel, at(4_000));
    assert!(!epoch.path(at(4_600)));
    assert_eq!(epoch.reassertions, 1);
    // The rebuild binds to the re-pinned interface and takes over.
    assert!(epoch.tick_until(Duration::from_secs(5), |e| e.swaps == 1));
    assert_eq!(
        epoch.pinned.get(),
        Some(RelayInterface::for_test("en0", lo0.index()))
    );
    assert_eq!(epoch.lifecycle.phase, Phase::Running);
    assert!(epoch.probe.ready());
    assert_eq!(first.phase(), SessionPhase::Joined);
    assert!(relay.accepts() >= 2);
    assert_eq!(
        (
            epoch.applied,
            epoch.reassertions,
            epoch.cancels,
            epoch.swaps
        ),
        (1, 1, 0, 1)
    );
    assert!(epoch.stop());
    assert!(!store_locked(&tree.identity_dir()));
}

#[test]
fn a_new_primary_moves_a_pin_taken_on_the_primary_and_rebuilds_exactly_once() {
    // v33: the epoch's pinned interface is the path's only (primary) egress;
    // another interface then becomes primary while the pin keeps its
    // address. The loopback relay is reachable only over lo0, so the "new"
    // interfaces carry lo0's index under their own names.
    let (relay, tree) = gated_relay(Arc::new(AtomicBool::new(true)));
    let mut epoch = Epoch::start(tree.clone(), None);
    let lo0 = RelayInterface::loopback_for_test().index();
    let first = epoch.probe.clone();
    let sink = epoch.watch.sink();
    let start = Instant::now();
    let at = |ms: u64| start + Duration::from_millis(ms);
    let pinned = egress("lo0", lo0, &[v4(127, 0, 0, 1)]);
    let wired = egress("en7", lo0, &[v4(192, 168, 1, 107)]);
    Watch::feed(
        &sink,
        PathObservation {
            usable: vec![pinned.clone()],
        },
        at(0),
    );
    assert!(!epoch.path(at(600)));
    let plugged = PathObservation {
        usable: vec![wired.clone(), pinned.clone()],
    };
    Watch::feed(&sink, plugged.clone(), at(1_000));
    assert!(!epoch.path(at(1_499)));
    assert!(epoch.path(at(1_500)));
    assert_eq!(epoch.reassertions, 1);
    assert_eq!(epoch.lifecycle.phase, Phase::Reasserting);
    assert_eq!(
        first.phase_reader().snapshot().1,
        Some("relay_path_changed")
    );
    assert_eq!(
        epoch.pinned.get(),
        Some(RelayInterface::for_test("en7", lo0))
    );
    // The same path again: no second re-pin or rebuild.
    Watch::feed(&sink, plugged, at(2_000));
    assert!(!epoch.path(at(2_600)));
    assert_eq!(epoch.reassertions, 1);
    // The rebuild binds to the new primary and takes over.
    assert!(epoch.tick_until(Duration::from_secs(5), |e| e.swaps == 1));
    assert_eq!(epoch.lifecycle.phase, Phase::Running);
    assert!(epoch.probe.ready());
    assert_eq!(first.phase(), SessionPhase::Joined);
    // The re-pinned interface is the primary: it follows the next move too.
    let second = epoch.probe.clone();
    Watch::feed(
        &sink,
        PathObservation {
            usable: vec![egress("en0", lo0, &[v4(192, 168, 1, 168)]), wired, pinned],
        },
        at(3_000),
    );
    assert!(epoch.path(at(3_600)));
    assert_eq!(
        second.phase_reader().snapshot().1,
        Some("relay_path_changed")
    );
    assert!(epoch.tick_until(Duration::from_secs(5), |e| e.swaps == 2));
    assert_eq!(
        epoch.pinned.get(),
        Some(RelayInterface::for_test("en0", lo0))
    );
    assert!(epoch.probe.ready());
    assert!(relay.accepts() >= 3);
    assert_eq!(
        (
            epoch.applied,
            epoch.reassertions,
            epoch.cancels,
            epoch.swaps
        ),
        (1, 2, 0, 2)
    );
    assert!(epoch.stop());
    assert!(!store_locked(&tree.identity_dir()));
}

#[test]
fn a_rebuild_attempt_bound_before_a_reasserting_repin_is_never_swapped_in() {
    let (_relay, tree) = gated_relay(Arc::new(AtomicBool::new(true)));
    let mut epoch = Epoch::start(tree.clone(), None);
    let lo0 = RelayInterface::loopback_for_test().index();
    let wifi = RelayInterface::for_test("en0", lo0);
    // The first rebuilt session binds its relay sockets to the pin, and the
    // epoch is re-pinned right after, while it constructs: path_changed_on_main
    // leaves a reasserting epoch's attempt alone (NextAttempt).
    let pins = epoch.pinned.clone();
    let fired = Arc::new(AtomicBool::new(false));
    let (trace, steps) = recorder();
    let once = fired.clone();
    let target = wifi.clone();
    epoch.rebuild_trace = Some(Arc::new(move |step| {
        trace(step);
        if step == "relay_interface_pinned" && !once.swap(true, Ordering::SeqCst) {
            assert_eq!(repin_effect(Phase::Reasserting), RepinEffect::NextAttempt);
            pins.repin(&target);
        }
    }));
    epoch.probe.seal("session_packet_terminal");
    epoch.lost();
    assert_eq!(epoch.lifecycle.phase, Phase::Reasserting);
    // That attempt reaches its ACK on the old pin but is refused before
    // Ready; the next one binds to the new pin and is swapped in.
    assert!(epoch.tick_until(Duration::from_secs(8), |e| e.swaps == 1));
    assert!(fired.load(Ordering::SeqCst));
    assert_eq!(
        epoch.swapped_attempts, 2,
        "the attempt bound before the re-pin was swapped in"
    );
    assert!(count(&steps, "dial") >= 2);
    assert_eq!(epoch.pinned.get(), Some(wifi));
    // The swapped-in session is current: it stays live across monitor ticks.
    thread::sleep(Duration::from_millis(700));
    epoch.tick();
    assert!(
        epoch.probe.ready(),
        "{:?}",
        epoch.probe.phase_reader().snapshot()
    );
    assert_eq!((epoch.swaps, epoch.cancels), (1, 0));
    assert!(epoch.stop());
    assert!(!store_locked(&tree.identity_dir()));
}

#[test]
fn a_ready_session_bound_before_a_repin_seals_itself_and_is_rebuilt() {
    let (_relay, tree) = gated_relay(Arc::new(AtomicBool::new(true)));
    let mut epoch = Epoch::start(tree.clone(), None);
    let first = epoch.probe.clone();
    let lo0 = RelayInterface::loopback_for_test().index();
    // A re-pin the session's owner never sealed it for (it was Ready but
    // not yet swapped in while the epoch was reasserting).
    epoch.pinned.repin(&RelayInterface::for_test("en0", lo0));
    assert!(wait_until(Duration::from_secs(2), || !first.ready()).is_some());
    assert_eq!(
        first.phase_reader().snapshot().1,
        Some("relay_path_changed")
    );
    // Recoverable: the drain observation rebuilds it on the new pin.
    assert!(epoch.tick_until(Duration::from_secs(5), |e| e.swaps == 1));
    assert_eq!((epoch.reassertions, epoch.cancels), (1, 0));
    assert!(epoch.probe.ready());
    assert!(epoch.stop());
    assert!(!store_locked(&tree.identity_dir()));
}

#[test]
fn a_repin_strands_the_current_sessions_relay_sessions_for_the_epoch() {
    let pins = EpochPins::pinned_for_test(RelayInterface::for_test("en7", 7));
    let limiter = crate::establish_limit::EstablishLimiter::new(pins.auth_backoff());
    let flows = (limiter.live_flow().unwrap(), limiter.live_flow().unwrap());
    let generation = pins.generation();
    pins.repin(&RelayInterface::for_test("en0", 11));
    assert_eq!(pins.generation(), generation.wrapping_add(1));
    assert_eq!(pins.auth_backoff().stranded_now(), 2);
    // A second re-pin before that session ended counts it only once.
    pins.repin(&RelayInterface::for_test("en7", 7));
    assert_eq!(pins.auth_backoff().stranded_now(), 2);
    drop(flows);
}
