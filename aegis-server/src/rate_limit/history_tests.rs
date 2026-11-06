use super::*;
use std::net::{Ipv4Addr, Ipv6Addr};

const EXPECTED_HISTORY_CAPACITY: usize = 4096;

fn synthetic_ipv6(index: usize) -> IpAddr {
    IpAddr::V6(Ipv6Addr::from(
        0x20010db8000000000000000000000000_u128 + index as u128,
    ))
}

#[tokio::test]
async fn auth_history_bounds_rotating_ipv6_failures_without_eviction() {
    let rl = RateLimiter::new(2, 300, true);
    let now = Instant::now();
    let banned = synthetic_ipv6(0);
    rl.record_failure_at(banned, now).await;
    rl.record_failure_at(banned, now).await;
    for index in 1..(EXPECTED_HISTORY_CAPACITY + 513) {
        rl.record_failure_at(synthetic_ipv6(index), now).await;
    }
    assert!(
        rl.inner.lock().await.entries.len() <= EXPECTED_HISTORY_CAPACITY,
        "rotating failed-auth IPv6 identities must not grow history beyond the fixed cap"
    );
    assert!(
        rl.is_banned_at(banned, now).await,
        "history pressure must preserve active bans"
    );
}

#[tokio::test]
async fn auth_history_saturation_denies_unknown_and_preserves_known_under_threshold() {
    let rl = RateLimiter::new(2, 300, true);
    let now = Instant::now();
    let known = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));
    rl.record_failure_at(known, now).await;
    for index in 0..(EXPECTED_HISTORY_CAPACITY - 1) {
        rl.record_failure_at(synthetic_ipv6(index), now).await;
    }
    let unknown = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 25));
    assert!(
        rl.is_banned_at(unknown, now).await,
        "full auth history must explicitly deny untracked identities instead of silently losing their future failures"
    );
    assert!(
        !rl.is_banned_at(known, now).await,
        "tracked identity below its threshold must remain usable"
    );
    assert_eq!(
        rl.inner.lock().await.entries.len(),
        EXPECTED_HISTORY_CAPACITY
    );
}

#[tokio::test]
async fn auth_history_failure_count_cannot_wrap_and_unban_identity() {
    let rl = RateLimiter::new(2, 300, true);
    let now = Instant::now();
    let ip = synthetic_ipv6(5);
    rl.record_failure_at(ip, now).await;
    rl.inner.lock().await.entries.get_mut(&ip).unwrap().0 = u32::MAX;
    rl.record_failure_at(ip, now).await;
    assert!(rl.is_banned_at(ip, now).await);
    assert_eq!(rl.inner.lock().await.entries.get(&ip).unwrap().0, u32::MAX);
}

#[tokio::test]
async fn auth_history_ban_check_reclaims_expiry_and_recovers_unknown_admission() {
    let rl = RateLimiter::new(2, 300, true);
    let now = Instant::now();
    for index in 0..EXPECTED_HISTORY_CAPACITY {
        rl.record_failure_at(synthetic_ipv6(index), now).await;
    }
    let unknown = "198.51.100.25".parse().unwrap();
    assert!(
        rl.is_banned_at(unknown, now + Duration::from_secs(299))
            .await
    );
    assert!(
        !rl.is_banned_at(unknown, now + Duration::from_secs(300))
            .await
    );
    {
        let inner = rl.inner.lock().await;
        assert!(inner.entries.is_empty());
        assert!(inner.expiry.is_empty());
        assert!(!inner.saturation_warned);
    }
    rl.record_failure_at(unknown, now + Duration::from_secs(300))
        .await;
    assert!(
        !rl.is_banned_at(unknown, now + Duration::from_secs(301))
            .await
    );
    rl.record_failure_at(unknown, now + Duration::from_secs(301))
        .await;
    assert!(
        rl.is_banned_at(unknown, now + Duration::from_secs(599))
            .await
    );
    assert!(
        !rl.is_banned_at(unknown, now + Duration::from_secs(600))
            .await
    );
}

#[tokio::test]
async fn auth_history_new_failure_reclaims_expired_capacity_without_cleanup_task() {
    let rl = RateLimiter::new(2, 300, true);
    let now = Instant::now();
    for index in 0..EXPECTED_HISTORY_CAPACITY {
        rl.record_failure_at(synthetic_ipv6(index), now).await;
    }
    let fresh = "192.0.2.40".parse().unwrap();
    let after_expiry = now + Duration::from_secs(300);
    rl.record_failure_at(fresh, after_expiry).await;
    let inner = rl.inner.lock().await;
    assert_eq!(inner.entries.len(), 1);
    assert_eq!(inner.expiry.len(), 1);
    assert_eq!(inner.entries.get(&fresh), Some(&(1, after_expiry)));
    assert!(!inner.saturation_warned);
}

#[tokio::test]
async fn auth_history_repeated_failures_keep_one_expiry_and_do_not_extend_window() {
    let rl = RateLimiter::new(3, 300, true);
    let now = Instant::now();
    let ip = synthetic_ipv6(15);
    for seconds in 0..200 {
        rl.record_failure_at(ip, now + Duration::from_secs(seconds))
            .await;
    }
    {
        let inner = rl.inner.lock().await;
        assert_eq!(inner.entries.len(), 1);
        assert_eq!(inner.expiry.len(), 1);
        assert_eq!(inner.entries.get(&ip), Some(&(200, now)));
    }
    assert!(rl.is_banned_at(ip, now + Duration::from_secs(299)).await);
    assert!(!rl.is_banned_at(ip, now + Duration::from_secs(300)).await);
    rl.record_failure_at(ip, now + Duration::from_secs(300))
        .await;
    let inner = rl.inner.lock().await;
    assert_eq!(inner.entries.len(), 1);
    assert_eq!(inner.expiry.len(), 1);
    assert_eq!(
        inner.entries.get(&ip),
        Some(&(1, now + Duration::from_secs(300)))
    );
}

#[tokio::test]
async fn auth_history_cleanup_preserves_unexpired_full_ipv6_identity_windows() {
    let rl = RateLimiter::new(2, 300, true);
    let now = Instant::now();
    let first = synthetic_ipv6(10);
    let adjacent = synthetic_ipv6(11);
    rl.record_failure_at(first, now).await;
    rl.record_failure_at(first, now).await;
    rl.record_failure_at(adjacent, now + Duration::from_secs(100))
        .await;
    assert!(rl.is_banned_at(first, now + Duration::from_secs(100)).await);
    assert!(
        !rl.is_banned_at(adjacent, now + Duration::from_secs(100))
            .await
    );
    rl.cleanup_at(now + Duration::from_secs(300)).await;
    assert!(!rl.is_banned_at(first, now + Duration::from_secs(300)).await);
    assert!(
        !rl.is_banned_at(adjacent, now + Duration::from_secs(300))
            .await
    );
    let inner = rl.inner.lock().await;
    assert_eq!(inner.entries.len(), 1);
    assert_eq!(inner.expiry.len(), 1);
    assert_eq!(
        inner.entries.get(&adjacent),
        Some(&(1, now + Duration::from_secs(100)))
    );
}

#[tokio::test]
async fn auth_history_saturation_preserves_trusted_proxy_and_shared_ip_policy() {
    let rl = RateLimiter::new(2, 300, true)
        .with_trusted_proxies(&["203.0.113.0/24".into()], "cf-connecting-ip")
        .unwrap();
    let now = Instant::now();
    let edge: SocketAddr = "203.0.113.10:443".parse().unwrap();
    let known: IpAddr = "198.51.100.10".parse().unwrap();
    rl.record_failure_at(known, now).await;
    for index in 0..(EXPECTED_HISTORY_CAPACITY - 1) {
        rl.record_failure_at(synthetic_ipv6(index), now).await;
    }
    let mut headers = http::HeaderMap::new();
    headers.insert("cf-connecting-ip", "198.51.100.10".parse().unwrap());
    assert!(
        !rl.is_banned_at(rl.http_identity(edge, &headers).unwrap(), now)
            .await
    );
    headers.insert("cf-connecting-ip", "198.51.100.11".parse().unwrap());
    assert!(
        rl.is_banned_at(rl.http_identity(edge, &headers).unwrap(), now)
            .await
    );
    assert_eq!(rl.socket_identity(edge), None);
    assert_eq!(rl.http_identity(edge, &http::HeaderMap::new()), None);
    assert!(!rl.is_socket_banned(edge).await);
    let first: SocketAddr = "198.51.100.10:40000".parse().unwrap();
    let second: SocketAddr = "198.51.100.10:40001".parse().unwrap();
    assert_eq!(rl.socket_identity(first), rl.socket_identity(second));
    let direct: SocketAddr = "192.0.2.9:443".parse().unwrap();
    assert_eq!(rl.http_identity(direct, &headers), Some(direct.ip()));
    let inner = rl.inner.lock().await;
    assert_eq!(inner.entries.len(), EXPECTED_HISTORY_CAPACITY);
    assert_eq!(inner.expiry.len(), EXPECTED_HISTORY_CAPACITY);
    assert!(inner.saturation_warned);
}
