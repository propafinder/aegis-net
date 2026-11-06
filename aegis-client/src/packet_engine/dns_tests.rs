//! B-06 build 37 endurance (2026-10-28, 121 cycles of 60 s): 34 HTTP probes
//! to `http://example.com/` failed with http=000 while whoami, the TCP and UDP
//! echoes and the TXT query (numeric targets, or relayed) never did. Each
//! failing probe's connect reached the engine more than 60.00 s after the
//! last DNS answer for the name (the engine's map lifetime) while macOS's
//! resolver still served that answer from its cache; every connect within
//! 60 s of it passed. These tests run on paused time: the map reads its clock
//! through tokio. They build maps as the engine does, with its recycle idle.
use super::*;

const POOL: &str = "198.18.0.0/16";
const IDLE: Duration = super::super::engine::FAKE_IP_RECYCLE_IDLE;
/// macOS's resolver keeps a unicast answer past its TTL (60 s here); the
/// endurance receipts show a 60 s answer used 67.6 s after it arrived.
const RESOLVER_GRACE: Duration = Duration::from_secs(60 + 60 / 4 + 2);

fn host_of(map: &FakeIpMap, ip: Ipv4Addr, port: u16) -> Option<String> {
    lease_target_host(SocketAddr::from((ip, port)), Some(map))
        .ok()
        .map(|(host, _lease)| host)
}

struct NoEvents;
impl aegis_client::packet_engine::services::EventSink for NoEvents {
    fn emit(
        &self,
        _: &'static str,
        _: aegis_client::packet_engine::services::EngineEvent,
        _: &'static str,
        _: serde_json::Value,
    ) {
    }
}

/// A one-question A query for `name`.
fn a_query(id: u16, name: &str) -> Vec<u8> {
    let mut query = id.to_be_bytes().to_vec();
    query.extend_from_slice(&[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]);
    for label in name.split('.') {
        query.push(u8::try_from(label.len()).unwrap());
        query.extend_from_slice(label.as_bytes());
    }
    query.extend_from_slice(&[0, 0, 1, 0, 1]);
    query
}

#[tokio::test(start_paused = true)]
async fn an_answered_address_keeps_its_name_long_past_the_answer_ttl() {
    let map = FakeIpMap::new(POOL, IDLE).unwrap();
    let (ip, _) = map.assign("example.com").unwrap();
    // The endurance window's failing connects came 60.00 to 62.6 s after
    // the answer; the resolver may serve it until its grace ends.
    tokio::time::advance(Duration::from_millis(60_010)).await;
    assert_eq!(host_of(&map, ip, 80).as_deref(), Some("example.com"));
    tokio::time::advance(RESOLVER_GRACE).await;
    assert_eq!(host_of(&map, ip, 80).as_deref(), Some("example.com"));
    // No timer takes a binding back: hours later it still means its name.
    tokio::time::advance(Duration::from_secs(5 * 3600)).await;
    assert_eq!(host_of(&map, ip, 443).as_deref(), Some("example.com"));
    let mapped = SocketAddr::new(ip.to_ipv6_mapped().into(), 443);
    assert_eq!(
        lease_target_host(mapped, Some(&map)).unwrap().0,
        "example.com",
        "an IPv4-mapped IPv6 destination is the same binding"
    );
}

#[tokio::test(start_paused = true)]
async fn a_name_keeps_its_address_across_answers() {
    let map = FakeIpMap::new(POOL, IDLE).unwrap();
    let (ip, new) = map.assign("example.com").unwrap();
    assert!(new);
    for wait in [61, 77, 600, 7200] {
        tokio::time::advance(Duration::from_secs(wait)).await;
        assert_eq!(
            map.assign("example.com"),
            Some((ip, false)),
            "answer {wait} s after the last one"
        );
    }
    assert_eq!(map.snapshot_size(), 1);
}

#[tokio::test(start_paused = true)]
async fn an_address_a_flow_or_reply_holds_is_never_recycled_and_idles_from_its_end() {
    // One usable address, so any other name could only take this one.
    let map = FakeIpMap::new("198.19.255.252/30", IDLE).unwrap();
    let (ip, _) = map.assign("held.test").unwrap();
    let destination = SocketAddr::from((ip, 443));
    let (host, flow) = lease_target_host(destination, Some(&map)).unwrap();
    assert_eq!(host, "held.test");
    let queued_reply = flow.clone();
    tokio::time::advance(Duration::from_secs(10 * 3600)).await;
    assert!(map.assign("other.test").is_none(), "a held address stays");
    drop(flow);
    assert!(
        map.assign("other.test").is_none(),
        "its reply still holds it"
    );
    drop(queued_reply);
    // The hold ended now: the idle time starts here, not at the lease.
    assert!(map.assign("other.test").is_none());
    tokio::time::advance(IDLE - Duration::from_millis(1)).await;
    assert!(map.assign("other.test").is_none());
    assert_eq!(host_of(&map, ip, 443).as_deref(), Some("held.test"));
    // That lookup was a use too.
    tokio::time::advance(IDLE - Duration::from_millis(1)).await;
    assert!(map.assign("other.test").is_none());
    tokio::time::advance(Duration::from_millis(1)).await;
    assert_eq!(map.assign("other.test"), Some((ip, true)));
    assert_eq!(host_of(&map, ip, 443).as_deref(), Some("other.test"));
    assert!(
        map.assign("held.test").is_none(),
        "the old name has no address until another idles"
    );
}

/// The last lease's end marks its binding used under the map lock, after the
/// lease's count has already reached zero. An answer for another name that
/// holds the lock in between must still see the binding held: otherwise it
/// reads the use from before the flow (here two recycle idles ago) and
/// rebinds the address the very moment its flow ends.
#[tokio::test(start_paused = true)]
async fn an_address_whose_last_hold_is_ending_is_still_held() {
    let map = Arc::new(FakeIpMap::new("198.19.255.252/30", IDLE).unwrap());
    let (ip, _) = map.assign("ending.test").unwrap();
    let (_, flow) = lease_target_host(SocketAddr::from((ip, 443)), Some(&*map)).unwrap();
    tokio::time::advance(IDLE * 2).await;
    // An answer for another name takes the lock as the flow ends: the end
    // waits for it on another thread (the engine's runtime).
    let ending = {
        let inner = map.inner.lock().unwrap();
        let ending = tokio::task::spawn_blocking(move || drop(flow));
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while FakeIpMap::holders_for_test(&inner, ip) != 0 {
            assert!(
                std::time::Instant::now() < deadline,
                "the lease never ended"
            );
            std::thread::yield_now();
        }
        assert_eq!(
            map.recyclable(&inner, FakeIpInstant::now()),
            None,
            "a binding whose last hold is ending is recycled before that end marks it used"
        );
        ending
    };
    ending.await.unwrap();
    // The end marked it used: its idle time starts there.
    assert!(map.assign("other.test").is_none());
    tokio::time::advance(IDLE - Duration::from_millis(1)).await;
    assert!(map.assign("other.test").is_none());
    assert_eq!(host_of(&map, ip, 443).as_deref(), Some("ending.test"));
}

#[tokio::test(start_paused = true)]
async fn lookups_by_address_mark_the_binding_used() {
    let map = FakeIpMap::new("198.19.255.252/30", IDLE).unwrap();
    let (ip, _) = map.assign("looked-up.test").unwrap();
    tokio::time::advance(IDLE * 9 / 10).await;
    assert_eq!(
        resolve_target_host(SocketAddr::from((ip, 443)), Some(&map)).unwrap(),
        "looked-up.test"
    );
    tokio::time::advance(IDLE * 9 / 10).await;
    assert!(map.assign("other.test").is_none());
}

#[tokio::test(start_paused = true)]
async fn recycling_takes_the_least_recently_used_idle_binding_and_only_when_none_is_fresh() {
    // /29: five usable addresses, 198.18.0.2 to 198.18.0.6.
    let map = Arc::new(FakeIpMap::new("198.18.0.0/29", IDLE).unwrap());
    let names = ["n1", "n2", "n3", "n4", "n5"];
    let ips: Vec<Ipv4Addr> = names.iter().map(|n| map.assign(n).unwrap().0).collect();
    // In sixtieths of the recycle idle (minutes of the hour): last uses n5 at
    // 0, n4 at 10, n3 at 20, n1 (an answer) and n2 (a flow) at 50.
    let at = |sixtieths: u32| IDLE * sixtieths / 60;
    tokio::time::advance(at(10)).await;
    map.assign("n4").unwrap();
    tokio::time::advance(at(10)).await;
    map.assign("n3").unwrap();
    tokio::time::advance(at(30)).await;
    map.assign("n1").unwrap();
    drop(lease_target_host(SocketAddr::from((ips[1], 443)), Some(&*map)).unwrap());
    tokio::time::advance(at(31)).await;
    // n5, n4 and n3 have idled 81, 71 and 61; n1 and n2 31.
    assert_eq!(map.assign("n6"), Some((ips[4], true)));
    assert_eq!(map.assign("n7"), Some((ips[3], true)));
    assert_eq!(map.assign("n8"), Some((ips[2], true)));
    assert!(map.assign("n9").is_none(), "no binding idled long enough");
    for (name, ip) in [("n1", ips[0]), ("n2", ips[1]), ("n6", ips[4])] {
        assert_eq!(host_of(&map, ip, 443).as_deref(), Some(name));
    }
    // A full pool answers SERVFAIL, never an address in use.
    let answer = build_response_with_sink(&a_query(0x5a5a, "n9.test"), &map, 60, &NoEvents);
    assert_eq!(&answer[..2], &[0x5a, 0x5a]);
    assert_eq!(answer[3] & 0x0f, 2, "rcode SERVFAIL");
    assert_eq!(u16::from_be_bytes([answer[6], answer[7]]), 0, "no answer");
    assert_eq!(map.snapshot_size(), 5);
}

#[test]
fn addresses_never_answered_or_outside_the_pool_fail_closed() {
    let map = FakeIpMap::new(POOL, IDLE).unwrap();
    let (ip, _) = map.assign("bound.test").unwrap();
    let never = Ipv4Addr::from(u32::from(ip) + 1);
    assert!(lease_target_host(SocketAddr::from((never, 443)), Some(&map)).is_err());
    assert!(lease_target_host("198.19.0.2:443".parse().unwrap(), Some(&map)).is_err());
    assert!(lease_target_host(SocketAddr::from((ip, 443)), None).is_err());
    assert_eq!(
        lease_target_host("203.0.113.9:443".parse().unwrap(), None)
            .unwrap()
            .0,
        "203.0.113.9"
    );
}

#[test]
fn a_random_start_gives_out_every_address_once_before_any_recycling() {
    let size = 8 - 3;
    for offset in [0, 1, 4, 5, u32::MAX] {
        let map = FakeIpMap::new("198.18.0.0/29", IDLE)
            .unwrap()
            .starting_at(offset);
        let mut seen: Vec<u32> = (0..size)
            .map(|i| u32::from(map.assign(&format!("h{i}")).unwrap().0))
            .collect();
        assert!(map.assign("one-more").is_none());
        seen.sort_unstable();
        let first = u32::from(Ipv4Addr::new(198, 18, 0, 2));
        assert_eq!(
            seen,
            (first..first + size).collect::<Vec<_>>(),
            "offset {offset}"
        );
    }
}
