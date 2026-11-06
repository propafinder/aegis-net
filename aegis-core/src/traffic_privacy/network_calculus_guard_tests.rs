use super::*;
fn settings() -> Settings {
    Settings {
        burst_bytes: 10,
        arrival_rate_bytes_per_second: 3,
        service_rate_bytes_per_second: 6,
        service_latency_ns: 1_000_000_000,
    }
}

#[test]
fn exact_conditional_bounds_round_up_not_down() {
    let b = settings().theoretical_bounds().unwrap();
    assert_eq!(b.backlog_bytes_ceiling, 13);
    assert_eq!(b.fifo_delay_ns_ceiling, 2_666_666_667);
    assert!(!b.guaranteed_service_verified);
    assert!(b.requires_fifo_rate_latency_service);
    let mut s = settings();
    s.service_latency_ns = 1;
    let b = s.theoretical_bounds().unwrap();
    assert_eq!(b.backlog_bytes_ceiling, 11);
    assert_eq!(b.fifo_delay_ns_ceiling, 1_666_666_668);
    s.service_rate_bytes_per_second = 3;
    assert!(s.theoretical_bounds().is_ok());
    s.service_rate_bytes_per_second = 2;
    assert_eq!(s.theoretical_bounds(), Err(GuardError::Parameters));
}
#[test]
fn finite_parameter_and_local_ceiling_admission() {
    let s = settings();
    assert!(s.validate_local_ceiling(3, 500_000_000).is_ok());
    assert!(s.validate_local_ceiling(2, 500_000_000).is_err());
    assert!(s.validate_local_ceiling(6, 2_000_000_000).is_err());
    for (bytes, period) in [
        (0, 1),
        (1, 0),
        (MAX_BURST_BYTES + 1, 1),
        (1, MAX_LIFETIME_NS + 1),
    ] {
        assert!(s.validate_local_ceiling(bytes, period).is_err());
    }
    for field in 0..5 {
        let mut s = settings();
        match field {
            0 => s.burst_bytes = 0,
            1 => s.burst_bytes = MAX_BURST_BYTES + 1,
            2 => s.arrival_rate_bytes_per_second = MAX_RATE_BYTES_PER_SECOND + 1,
            3 => s.service_rate_bytes_per_second = 0,
            _ => s.service_latency_ns = MAX_LIFETIME_NS + 1,
        };
        assert_eq!(s.validate(), Err(GuardError::Parameters));
    }
    assert_eq!(
        ArrivalGuard::new(settings(), u64::MAX).err(),
        Some(GuardError::Overflow)
    );
}
#[test]
fn fractional_refill_preserved_and_rejection_cannot_borrow() {
    let mut g = ArrivalGuard::new(settings(), 0).unwrap();
    g.admit(0, 10).unwrap();
    let before = g.snapshot().unwrap();
    assert_eq!(g.admit(333_333_333, 1), Err(GuardError::BurstExceeded));
    assert_eq!(g.snapshot().unwrap(), before);
    g.admit(333_333_334, 1).unwrap();
    assert_eq!(g.tokens_scaled, 2);
    g.admit(666_666_667, 1).unwrap();
    assert_eq!(g.tokens_scaled, 1);
    g.admit(1_000_000_000, 1).unwrap();
    assert_eq!(g.tokens_scaled, 0);
    assert_eq!(g.admit(1_000_000_000, 1), Err(GuardError::BurstExceeded));
}
#[test]
fn sustained_over_rate_is_refused_despite_recent_burst_admission() {
    let mut s = settings();
    s.burst_bytes = 4;
    s.arrival_rate_bytes_per_second = 2;
    let mut g = ArrivalGuard::new(s, 0).unwrap();
    g.admit(0, 4).unwrap();
    g.admit(500_000_000, 1).unwrap();
    let before = g.snapshot().unwrap();
    assert_eq!(g.admit(500_000_001, 1), Err(GuardError::BurstExceeded));
    assert_eq!(g.snapshot().unwrap(), before);
    g.admit(1_000_000_000, 1).unwrap();
    assert_eq!(g.snapshot().unwrap().cumulative_admitted_bytes, 6);
}
#[test]
fn idle_time_cannot_accumulate_more_than_burst_and_zero_rate_is_finite() {
    let mut g = ArrivalGuard::new(settings(), 0).unwrap();
    g.admit(0, 10).unwrap();
    g.admit(100_000_000_000, 10).unwrap();
    assert_eq!(g.admit(100_000_000_000, 1), Err(GuardError::BurstExceeded));
    let mut s = settings();
    s.arrival_rate_bytes_per_second = 0;
    let mut g = ArrivalGuard::new(s, 0).unwrap();
    g.admit(0, 9).unwrap();
    g.admit(MAX_LIFETIME_NS - 1, 1).unwrap();
    assert_eq!(
        g.admit(MAX_LIFETIME_NS - 1, 1),
        Err(GuardError::BurstExceeded)
    );
}
#[test]
fn backward_clock_expiry_and_invalid_bytes_are_transactional() {
    let mut g = ArrivalGuard::new(settings(), 25).unwrap();
    g.admit(30, 1).unwrap();
    let before = g.snapshot().unwrap();
    for (at, n, expected) in [
        (29, 1, GuardError::Clock),
        (25 + MAX_LIFETIME_NS, 1, GuardError::Clock),
        (30, 0, GuardError::Arrival),
        (30, 11, GuardError::Arrival),
    ] {
        assert_eq!(g.admit(at, n), Err(expected));
        assert_eq!(g.snapshot().unwrap(), before);
    }
}
#[test]
fn service_failure_invalidates_future_conditional_receipt_without_reset() {
    let mut g = ArrivalGuard::new(settings(), 0).unwrap();
    let receipt = g.admit(0, 1).unwrap();
    assert!(!receipt.guaranteed_service_verified);
    g.service_failed();
    g.service_failed();
    let s = g.snapshot().unwrap();
    assert!(s.service_premise_invalidated);
    assert!(s.conditional_bounds.is_none());
    assert_eq!(g.admit(1, 1), Err(GuardError::ServiceInvalidated));
    assert_eq!(g.snapshot().unwrap(), s);
}
#[test]
fn every_observed_interval_respects_exact_arrival_envelope() {
    let s = settings();
    let mut g = ArrivalGuard::new(s.clone(), 0).unwrap();
    let mut tape = vec![(0_u64, 0_u64)];
    let mut sum = 0;
    for i in 0..512 {
        let t = i * 125_000_000;
        let bytes = if i % 7 == 0 { 2 } else { 1 };
        if g.admit(t, bytes).is_ok() {
            sum += bytes;
            tape.push((t, sum));
        }
    }
    assert!(tape.len() > 150);
    for &(a, x) in &tape {
        for &(b, y) in &tape {
            if b >= a && y >= x {
                assert!(
                    u128::from(y - x) * NS_PER_SECOND
                        <= u128::from(s.burst_bytes) * NS_PER_SECOND
                            + u128::from(s.arrival_rate_bytes_per_second) * u128::from(b - a)
                );
            }
        }
    }
}
#[test]
fn count_and_byte_overflow_refuse_before_accounting_change() {
    let mut g = ArrivalGuard::new(settings(), 0).unwrap();
    g.count = MAX_ADMISSIONS;
    let before = g.snapshot().unwrap();
    assert_eq!(g.admit(1, 1), Err(GuardError::Capacity));
    assert_eq!(g.snapshot().unwrap(), before);
    g.count = 0;
    g.total = u64::MAX;
    let before = g.snapshot().unwrap();
    assert_eq!(g.admit(1, 1), Err(GuardError::Overflow));
    assert_eq!(g.snapshot().unwrap(), before);
    assert_eq!(ceil_div(u128::MAX, 2), Err(GuardError::Overflow));
    assert_eq!(ceil_div(1, 0), Err(GuardError::Parameters));
}
#[test]
fn settings_wire_roundtrip_is_exact_and_unknown_fields_refuse() {
    let s = settings();
    let v = serde_json::to_value(&s).unwrap();
    assert_eq!(serde_json::from_value::<Settings>(v.clone()).unwrap(), s);
    let mut v = v;
    v["guaranteed_service"] = serde_json::json!(true);
    assert!(serde_json::from_value::<Settings>(v).is_err());
}
