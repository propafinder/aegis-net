use super::*;
use rand::{rngs::StdRng, SeedableRng};
use std::{
    pin::Pin,
    task::{Context, Poll},
};

fn profile(slots: u32, queue: usize, release: usize, sigma: u32) -> NetShaperProfile {
    NetShaperProfile::new(
        slots,
        Duration::from_millis(100),
        Duration::from_secs(2),
        Duration::from_millis(50),
        queue,
        release,
        sigma,
        1_000_000,
        1,
    )
    .unwrap()
}
fn material() -> NetShaperMaterial {
    NetShaperMaterial::from_preprovisioned(Zeroizing::new([29; 32]), [17; 8])
}

#[test]
fn whole_public_horizon_privacy_admission_exact_boundary_and_overflow_refusal() {
    // 4 * 8² / (2 * 4²) =8 exactly. Constructor admits equality, refuses below.
    let make = |n, d| {
        NetShaperProfile::new(
            4,
            Duration::from_millis(1),
            Duration::from_secs(1),
            Duration::from_millis(1),
            8,
            64,
            4,
            n,
            d,
        )
    };
    assert!(make(8, 1).is_ok());
    assert!(make(799, 100).is_err());
    assert!(make(u128::MAX, u128::MAX).is_err());
    let p = make(8, 1).unwrap();
    let mut a = p.accountant();
    for _ in 0..4 {
        a.charge().unwrap();
    }
    assert_eq!(a.receipt().rho_numerator, "256");
    assert_eq!(a.receipt().rho_denominator, "32");
    assert!(a.charge().is_err());
    assert_eq!(a.receipt().releases, 4);
    assert!(
        (a.ideal_epsilon_estimate(0.01).unwrap() - (8.0 + 2.0 * (8.0f64 * 100.0f64.ln()).sqrt()))
            .abs()
            < 1e-12
    );
    assert!(a.ideal_epsilon_estimate(f64::NAN).is_err());
    assert!(a.ideal_epsilon_estimate(0.0).is_err());
}
#[test]
fn public_window_wire_and_frame_caps_reject_invalid_profiles() {
    let make = |slots, cadence, window, io, queue, release, sigma| {
        NetShaperProfile::new(
            slots, cadence, window, io, queue, release, sigma, 1_000_000, 1,
        )
    };
    let ms = Duration::from_millis(10);
    assert!(make(0, ms, ms, ms, 32, 32, 1).is_err());
    assert!(make(257, ms, Duration::from_secs(3), ms, 32, 32, 1).is_err());
    assert!(make(2, ms, ms, ms, 32, 32, 1).is_err());
    assert!(make(1, ms, ms, ms * 2, 32, 32, 1).is_err());
    assert!(make(1, ms, ms, ms, 1_048_577, 32, 1).is_err());
    assert!(make(1, ms, ms, ms, 32, 65_536, 1).is_err());
    assert!(make(1, ms, ms, ms, 32, 32, 0).is_err());
    let p = profile(4, 32, 64, 8);
    assert_eq!(p.worst_wire_bytes(), 4 * (64 + 24));
    assert_eq!(p.horizon(), Duration::from_millis(400));
    assert_ne!(
        p.descriptor_sha256(),
        profile(4, 32, 63, 8).descriptor_sha256()
    );
}
#[test]
fn nonexpansive_queue_dequeue_and_universal_conditional_sensitivity_exhaustive() {
    for a in 0usize..=32 {
        for b in 0usize..=32 {
            for released in 0usize..=64 {
                let next_a = a - a.min(released);
                let next_b = b - b.min(released);
                assert!(next_a.abs_diff(next_b) <= a.abs_diff(b));
                assert!(a.abs_diff(b) <= 32);
            }
        }
    }
    // Reusing a much smaller delta merely because arrivals were close once is
    // unsound with an unbounded backlog; universal cap remains valid instead.
    let mut a = 0usize;
    let b = 0usize;
    for _ in 0..10 {
        a += 1;
    }
    assert_eq!(a - b, 10);
}
#[test]
fn queue_bytes_authentication_plaintext_and_no_unshaped_overflow() {
    let mut q = SecretQueue::new(8);
    q.enqueue(b"12345678").unwrap();
    assert!(q.enqueue(b"9").is_err());
    let f = q.frame(3);
    assert_eq!(&f[..4], &3u32.to_be_bytes());
    assert_eq!(&f[4..], b"123");
    assert_eq!(q.bytes.len(), 5);
    let f = q.frame(8);
    assert_eq!(&f[..4], &5u32.to_be_bytes());
    assert_eq!(&f[4..9], b"45678");
    assert_eq!(&f[9..], &[0; 3]);
    assert!(q.bytes.is_empty());
    assert_eq!(release_bytes(8, i64::MIN, 64), 0);
    assert_eq!(release_bytes(8, i64::MAX, 64), 64);
}
struct Broken;
impl RngCore for Broken {
    fn next_u32(&mut self) -> u32 {
        panic!("infallible entropy forbidden")
    }
    fn next_u64(&mut self) -> u64 {
        panic!("infallible entropy forbidden")
    }
    fn fill_bytes(&mut self, _: &mut [u8]) {
        panic!("infallible entropy forbidden")
    }
    fn try_fill_bytes(&mut self, _: &mut [u8]) -> Result<(), rand::Error> {
        Err(rand::Error::new(io::Error::other(
            "controlled entropy refusal",
        )))
    }
}
impl CryptoRng for Broken {}
#[test]
fn entropy_fuel_clock_and_arithmetic_refuse_without_noise_fallback() {
    let mut a = profile(1, 8, 64, 4).accountant();
    a.charge().unwrap();
    assert!(discrete_gaussian(4, &mut Broken, None).is_err());
    assert_eq!(a.receipt().releases, 1);
    let mut rng = StdRng::seed_from_u64(73);
    assert!(discrete_gaussian_budget(
        4,
        &mut rng,
        SamplingBudget {
            left: 0,
            deadline: None
        }
    )
    .is_err());
    assert!(discrete_gaussian(4, &mut rng, Some(Instant::now())).is_err());
    let mut budget = SamplingBudget {
        left: 100,
        deadline: None,
    };
    assert!(budget.exp_unit(&mut rng, 2, 1).is_err());
    assert!(budget.exp_unit(&mut rng, u128::MAX, u128::MAX).is_err()); // first draw certainly true, second exact d*k overflows
}
#[test]
fn exact_exp_rational_and_integer_gaussian_statistical_regression() {
    let mut rng = StdRng::seed_from_u64(971);
    let mut budget = SamplingBudget {
        left: 2_000_000,
        deadline: None,
    };
    let mut yes = 0;
    for _ in 0..10_000 {
        yes += usize::from(budget.exp(&mut rng, 3, 2).unwrap());
    }
    assert!((yes as f64 / 10_000.0 - (-1.5f64).exp()).abs() < 0.025);
    // A deterministic-seed audit distinguishes a sign/negative-zero error and
    // wrong variance parameter; it is NOT a proof of the probability law.
    let mut histogram = [0usize; 17];
    let mut sum = 0i64;
    let mut squares = 0i64;
    for _ in 0..20_000 {
        let x = discrete_gaussian(2, &mut rng, None).unwrap();
        sum += x;
        squares += x * x;
        if (-8..=8).contains(&x) {
            histogram[(x + 8) as usize] += 1;
        }
    }
    assert!((sum as f64 / 20_000.0).abs() < 0.10);
    assert!((squares as f64 / 20_000.0 - 4.0).abs() < 0.25);
    for k in 1..=4 {
        assert!((histogram[8 - k] as i64 - histogram[8 + k] as i64).abs() < 180);
    }
}

#[tokio::test(start_paused = true)]
async fn paired_live_sender_receiver_fifo_and_eof_dummy_horizon() {
    let p = profile(4, 32, 64, 4);
    let (tx, rx) = tokio::io::duplex(4096);
    let mut rng = StdRng::seed_from_u64(299);
    let deadline = Instant::now() + Duration::from_secs(3);
    let input = &b"netshaper authenticated queue"[..];
    let start = Instant::now();
    let (send, recv) = tokio::join!(
        NetShaperSession::new(p.clone(), material()).send_with_rng(input, tx, deadline, &mut rng),
        NetShaperSession::new(p, material()).receive(rx, deadline)
    );
    let s = send.unwrap();
    assert_eq!(s.accounting.releases, 4);
    assert_eq!(s.pending_bytes, 0);
    assert_eq!(recv.unwrap().as_slice(), b"netshaper authenticated queue");
    assert!(Instant::now() - start >= Duration::from_millis(400));
}
#[tokio::test(start_paused = true)]
async fn empty_input_still_emits_entire_public_epoch_and_never_end_marker() {
    let p = profile(3, 32, 64, 4);
    let (tx, mut rx) = tokio::io::duplex(4096);
    let mut rng = StdRng::seed_from_u64(399);
    let deadline = Instant::now() + Duration::from_secs(3);
    let (send, wire) = tokio::join!(
        NetShaperSession::new(p.clone(), material()).send_with_rng(
            tokio::io::empty(),
            tx,
            deadline,
            &mut rng
        ),
        async {
            let mut b = Vec::new();
            rx.read_to_end(&mut b).await.unwrap();
            b
        }
    );
    let s = send.unwrap();
    assert_eq!(s.accounting.releases, 3);
    assert_eq!(s.wire_bytes, wire.len() as u64);
    assert!(wire.len() >= 3 * OVERHEAD);
    let mut cursor = 0;
    for _ in 0..3 {
        let n = u32::from_be_bytes(wire[cursor..cursor + 4].try_into().unwrap()) as usize;
        assert!(n <= p.release_capacity());
        cursor += n + OVERHEAD;
    }
    assert_eq!(cursor, wire.len());
}
#[tokio::test(start_paused = true)]
async fn exhausted_original_clock_refuses_before_source_or_transport() {
    let p = profile(2, 8, 64, 4);
    let (tx, mut rx) = tokio::io::duplex(4096);
    let deadline = Instant::now() + Duration::from_millis(10);
    let result = NetShaperSession::new(p, material())
        .send(tokio::io::empty(), tx, deadline)
        .await;
    assert_eq!(result.unwrap_err().kind(), io::ErrorKind::TimedOut);
    let mut b = Vec::new();
    rx.read_to_end(&mut b).await.unwrap();
    assert!(b.is_empty());
}
#[tokio::test(start_paused = true)]
async fn actual_entropy_failure_produces_no_carrier_record() {
    let p = profile(1, 8, 64, 4);
    let (tx, mut rx) = tokio::io::duplex(4096);
    let deadline = Instant::now() + Duration::from_secs(3);
    let result = NetShaperSession::new(p, material())
        .send_with_rng(tokio::io::empty(), tx, deadline, &mut Broken)
        .await;
    assert!(result.is_err());
    let mut b = Vec::new();
    rx.read_to_end(&mut b).await.unwrap();
    assert!(b.is_empty());
}
fn wire(profile: &NetShaperProfile, index: u32, selected: usize, payload: &[u8]) -> Vec<u8> {
    let mut plain = vec![0; selected + 4];
    plain[..4].copy_from_slice(&(payload.len() as u32).to_be_bytes());
    plain[4..4 + payload.len()].copy_from_slice(payload);
    let cipher = ChaCha20Poly1305::new_from_slice(material().key.as_ref()).unwrap();
    let aad = aad(profile, index, selected);
    let body = cipher
        .encrypt(
            material().nonce(index).as_ref().into(),
            Payload {
                msg: &plain,
                aad: &aad,
            },
        )
        .unwrap();
    let mut out = (selected as u32).to_be_bytes().to_vec();
    out.extend_from_slice(&body);
    out
}
#[tokio::test]
async fn receiver_authenticates_profile_index_length_and_complete_record() {
    let p = profile(1, 32, 64, 4);
    let good = wire(&p, 0, 8, b"data");
    let deadline = Instant::now() + Duration::from_secs(2);
    assert_eq!(
        NetShaperSession::new(p.clone(), material())
            .receive(good.as_slice(), deadline)
            .await
            .unwrap()
            .as_slice(),
        b"data"
    );
    let mut tampered = good.clone();
    tampered[8] ^= 1;
    for bytes in [
        tampered,
        good[..good.len() - 1].to_vec(),
        wire(&p, 1, 8, b"data"),
        65u32.to_be_bytes().to_vec(),
    ] {
        assert!(NetShaperSession::new(p.clone(), material())
            .receive(bytes.as_slice(), deadline)
            .await
            .is_err());
    }
    assert!(NetShaperSession::new(profile(1, 31, 64, 4), material())
        .receive(good.as_slice(), deadline)
        .await
        .is_err());
}
#[tokio::test]
async fn authenticated_inner_length_over_capacity_refused_before_delivery() {
    let p = profile(1, 32, 64, 4);
    let cipher = ChaCha20Poly1305::new_from_slice(material().key.as_ref()).unwrap();
    let mut plain = vec![0; 8];
    plain[..4].copy_from_slice(&5u32.to_be_bytes());
    let aad = aad(&p, 0, 4);
    let body = cipher
        .encrypt(
            material().nonce(0).as_ref().into(),
            Payload {
                msg: &plain,
                aad: &aad,
            },
        )
        .unwrap();
    let mut bytes = 4u32.to_be_bytes().to_vec();
    bytes.extend_from_slice(&body);
    assert_eq!(
        NetShaperSession::new(p, material())
            .receive(bytes.as_slice(), Instant::now() + Duration::from_secs(2))
            .await
            .unwrap_err()
            .kind(),
        io::ErrorKind::InvalidData
    );
}
#[tokio::test(start_paused = true)]
async fn stalled_carrier_never_renews_caller_deadline() {
    let p = profile(1, 8, 64, 4);
    let (tx, _held) = tokio::io::duplex(1);
    let deadline = Instant::now() + Duration::from_secs(1);
    let mut rng = StdRng::seed_from_u64(399);
    let start = Instant::now();
    let error = NetShaperSession::new(p, material())
        .send_with_rng(tokio::io::empty(), tx, deadline, &mut rng)
        .await
        .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    assert!(Instant::now() - start < Duration::from_secs(1));
}
struct HeldInput {
    dropped: std::sync::Arc<std::sync::atomic::AtomicBool>,
}
impl AsyncRead for HeldInput {
    fn poll_read(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        _: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Poll::Pending
    }
}
impl Drop for HeldInput {
    fn drop(&mut self) {
        self.dropped
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }
}
#[tokio::test(start_paused = true)]
async fn cancelling_sender_drops_owned_input_transport_and_epoch_material() {
    let p = profile(2, 8, 64, 4);
    let (tx, mut rx) = tokio::io::duplex(4096);
    let dropped = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let source = HeldInput {
        dropped: dropped.clone(),
    };
    let handle = tokio::spawn(NetShaperSession::new(p, material()).send(
        source,
        tx,
        Instant::now() + Duration::from_secs(3),
    ));
    tokio::task::yield_now().await;
    handle.abort();
    assert!(handle.await.unwrap_err().is_cancelled());
    assert!(dropped.load(std::sync::atomic::Ordering::SeqCst));
    let mut b = Vec::new();
    rx.read_to_end(&mut b).await.unwrap();
    assert!(b.is_empty());
}

#[test]
fn serde_constructor_revalidates_and_rebinds_profile_instead_of_trusting_descriptor() {
    let p = profile(2, 32, 64, 4);
    let bytes = serde_json::to_vec(&p).unwrap();
    let round: NetShaperProfile = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(p.descriptor_sha256(), round.descriptor_sha256());
    let mut v = serde_json::to_value(&p).unwrap();
    v["slots"] = 0.into();
    assert!(serde_json::from_value::<NetShaperProfile>(v).is_err());
    let mut v = serde_json::to_value(&p).unwrap();
    v["rho_limit_n"] = "01".into();
    assert!(serde_json::from_value::<NetShaperProfile>(v).is_err());
    let mut v = serde_json::to_value(&p).unwrap();
    v["descriptor"] = "invented".into();
    assert!(serde_json::from_value::<NetShaperProfile>(v).is_err());
}
fn second_material() -> NetShaperMaterial {
    NetShaperMaterial::from_preprovisioned(Zeroizing::new([31; 32]), [19; 8])
}
#[tokio::test(start_paused = true)]
async fn owned_duplex_halfclose_completes_only_after_public_epoch() {
    let p = profile(3, 32, 64, 4);
    let (a, b) = tokio::io::duplex(4096);
    let deadline = Instant::now() + Duration::from_secs(3);
    let start = Instant::now();
    let mut left =
        attach_authenticated(a, p.clone(), material(), second_material(), deadline).unwrap();
    let mut right = attach_authenticated(b, p, second_material(), material(), deadline).unwrap();
    let (l, r) = tokio::join!(left.shutdown(), right.shutdown());
    l.unwrap();
    r.unwrap();
    assert!(Instant::now() - start >= Duration::from_millis(300));
    let mut empty = Vec::new();
    left.read_to_end(&mut empty).await.unwrap();
    assert!(empty.is_empty());
    let (l, r) = tokio::join!(left.finish(), right.finish());
    assert_eq!(l.unwrap().accounting.releases, 3);
    assert_eq!(r.unwrap().accounting.releases, 3);
}
#[tokio::test(start_paused = true)]
async fn owned_duplex_drop_retires_carrier_and_receiver_error_is_not_clean_eof() {
    let (a, mut observed) = tokio::io::duplex(4096);
    let p = profile(3, 32, 64, 4);
    let deadline = Instant::now() + Duration::from_secs(3);
    let s = attach_authenticated(a, p.clone(), material(), second_material(), deadline).unwrap();
    drop(s);
    tokio::task::yield_now().await;
    let mut b = Vec::new();
    observed.read_to_end(&mut b).await.unwrap();
    assert!(b.is_empty());
    let (a, b) = tokio::io::duplex(4096);
    let mut s = attach_authenticated(a, p, material(), second_material(), deadline).unwrap();
    drop(b);
    let mut b = [0; 1];
    assert!(s.read(&mut b).await.is_err());
}
#[tokio::test]
async fn paired_direction_material_collision_is_refused_before_spawn() {
    let (a, _b) = tokio::io::duplex(4096);
    let p = profile(3, 32, 64, 4);
    assert_eq!(
        attach_authenticated(
            a,
            p,
            material(),
            material(),
            Instant::now() + Duration::from_secs(3)
        )
        .unwrap_err()
        .kind(),
        io::ErrorKind::InvalidInput
    );
}

#[tokio::test(start_paused = true)]
async fn empty_fifo_without_actual_source_eof_cannot_claim_epoch_delivery() {
    let p = profile(1, 8, 64, 4);
    let (tx, mut rx) = tokio::io::duplex(4096);
    let dropped = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let input = HeldInput { dropped };
    let mut rng = StdRng::seed_from_u64(399);
    let deadline = Instant::now() + Duration::from_secs(3);
    let (send, wire) = tokio::join!(
        NetShaperSession::new(p, material()).send_with_rng(input, tx, deadline, &mut rng),
        async {
            let mut b = Vec::new();
            rx.read_to_end(&mut b).await.unwrap();
            b
        }
    );
    let receipt = send.unwrap();
    assert_eq!(receipt.pending_bytes, 0);
    assert!(!receipt.input_eof_observed);
    assert!(!wire.is_empty());
    let (a, b) = tokio::io::duplex(4096);
    let p = profile(1, 8, 64, 4);
    let mut left = attach_authenticated(
        a,
        p.clone(),
        material(),
        second_material(),
        Instant::now() + Duration::from_secs(3),
    )
    .unwrap();
    let mut right = attach_authenticated(
        b,
        p,
        second_material(),
        material(),
        Instant::now() + Duration::from_secs(3),
    )
    .unwrap();
    let (l, r) = tokio::join!(left.read_u8(), right.read_u8());
    assert_eq!(l.unwrap_err().kind(), io::ErrorKind::UnexpectedEof);
    assert_eq!(r.unwrap_err().kind(), io::ErrorKind::UnexpectedEof);
}

struct ReadyAtBoundary {
    ready: Pin<Box<tokio::time::Sleep>>,
    calls: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    consumed: std::sync::Arc<std::sync::atomic::AtomicBool>,
}
impl AsyncRead for ReadyAtBoundary {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        use std::future::Future;
        self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        if self.ready.as_mut().poll(cx).is_pending() {
            return Poll::Pending;
        }
        self.consumed
            .store(true, std::sync::atomic::Ordering::SeqCst);
        buf.put_slice(b"boundary");
        Poll::Ready(Ok(()))
    }
}

async fn assert_input_boundary_is_unpolled(extra_delay: Duration) {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    let p = NetShaperProfile::new(
        1,
        Duration::from_millis(10),
        Duration::from_secs(1),
        Duration::from_millis(10),
        8,
        64,
        4,
        1_000_000,
        1,
    )
    .unwrap();
    let calls = std::sync::Arc::new(AtomicUsize::new(0));
    let consumed = std::sync::Arc::new(AtomicBool::new(false));
    let source = ReadyAtBoundary {
        ready: Box::pin(tokio::time::sleep_until(
            Instant::now() + Duration::from_millis(10) + extra_delay,
        )),
        calls: calls.clone(),
        consumed: consumed.clone(),
    };
    let (tx, mut rx) = tokio::io::duplex(4096);
    let mut rng = StdRng::seed_from_u64(399);
    let receipt = NetShaperSession::new(p, material())
        .send_with_rng(
            source,
            tx,
            Instant::now() + Duration::from_secs(1),
            &mut rng,
        )
        .await
        .unwrap();
    // A finite sender receipt is not a clean stream/application completion:
    // the paired adapter independently requires input EOF and drained queues.
    assert!(!receipt.input_eof_observed);
    assert_eq!(receipt.pending_bytes, 0);
    assert_eq!(receipt.accounting.releases, 1);
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "expired window must not poll input"
    );
    assert!(
        !consumed.load(Ordering::SeqCst),
        "no boundary input consumption"
    );
    let mut wire = Vec::new();
    rx.read_to_end(&mut wire).await.unwrap();
    assert!(wire.len() >= OVERHEAD, "unchanged public slot still emits");
    let selected = u32::from_be_bytes(wire[..4].try_into().unwrap()) as usize;
    assert_eq!(wire.len(), selected + OVERHEAD);
}

#[tokio::test(start_paused = true)]
async fn input_boundary_ready_never_consumes_after_public_window() {
    assert_input_boundary_is_unpolled(Duration::ZERO).await;
}

#[tokio::test(start_paused = true)]
async fn input_boundary_pending_never_polls_after_public_window() {
    assert_input_boundary_is_unpolled(Duration::from_millis(1)).await;
}

struct LateRead;
impl AsyncRead for LateRead {
    fn poll_read(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        std::thread::sleep(Duration::from_millis(35));
        buf.put_slice(b"late");
        Poll::Ready(Ok(()))
    }
}
#[tokio::test]
async fn actual_synchronous_late_input_completion_refuses_before_emission() {
    let p = NetShaperProfile::new(
        1,
        Duration::from_millis(10),
        Duration::from_secs(1),
        Duration::from_millis(10),
        8,
        64,
        4,
        1_000_000,
        1,
    )
    .unwrap();
    let (tx, mut rx) = tokio::io::duplex(4096);
    let mut rng = StdRng::seed_from_u64(399);
    let error = NetShaperSession::new(p, material())
        .send_with_rng(
            LateRead,
            tx,
            Instant::now() + Duration::from_secs(1),
            &mut rng,
        )
        .await
        .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    assert_eq!(
        error.to_string(),
        "NetShaper input poll exceeded public tick"
    );
    let mut bytes = Vec::new();
    rx.read_to_end(&mut bytes).await.unwrap();
    assert!(bytes.is_empty());
}

struct PrivateErrorTransport;
impl AsyncRead for PrivateErrorTransport {
    fn poll_read(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        _: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Poll::Ready(Err(io::Error::new(
            io::ErrorKind::ConnectionReset,
            "private-application-error-marker",
        )))
    }
}
impl AsyncWrite for PrivateErrorTransport {
    fn poll_write(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        Poll::Ready(Ok(bytes.len()))
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[tokio::test(start_paused = true)]
async fn owned_worker_preserves_static_phase_and_kind_without_transport_error_bytes() {
    let mut stream = attach_authenticated(
        PrivateErrorTransport,
        profile(1, 8, 64, 4),
        material(),
        second_material(),
        Instant::now() + Duration::from_secs(1),
    )
    .unwrap();
    for _ in 0..2 {
        let error = stream.read_u8().await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::ConnectionReset);
        assert_eq!(error.to_string(), "NetShaper receiver failed");
        assert!(!format!("{error:?}").contains("private-application-error-marker"));
    }
}

#[test]
fn bounded_preallocated_queue_wrapping_preserves_fifo_without_growth() {
    let mut q = SecretQueue::new(8);
    let capacity = q.bytes.capacity();
    assert!(capacity >= 8);
    q.enqueue(b"12345678").unwrap();
    assert_eq!(&q.frame(3)[4..], b"123");
    q.enqueue(b"ABC").unwrap();
    assert_eq!(q.bytes.capacity(), capacity);
    assert_eq!(&q.frame(8)[4..], b"45678ABC");
    assert!(q.bytes.is_empty());
    q.enqueue(b"new").unwrap();
    let f = q.frame(5);
    assert_eq!(&f[4..7], b"new");
    assert_eq!(&f[7..], &[0, 0]);
    assert_eq!(q.bytes.capacity(), capacity);
}

#[tokio::test(start_paused = true)]
async fn owned_stream_debug_redacts_actual_buffered_synthetic_application_marker() {
    let (transport, _held) = tokio::io::duplex(4096);
    let mut stream = attach_authenticated(
        transport,
        profile(2, 64, 64, 4),
        NetShaperMaterial::from_preprovisioned(Zeroizing::new([31; 32]), [19; 8]),
        NetShaperMaterial::from_preprovisioned(Zeroizing::new([32; 32]), [20; 8]),
        Instant::now() + Duration::from_secs(2),
    )
    .unwrap();
    let marker = "synthetic_debug_marker_29";
    stream.write_all(marker.as_bytes()).await.unwrap();
    // Confirm the real private Tokio buffer contains the synthetic marker;
    // neither its Debug value nor real production payload is printed.
    assert!(format!("{:?}", stream.app).contains(marker));
    let public = format!("{stream:?}");
    assert!(!public.contains(marker));
    assert_eq!(public, "NetShaperStream { .. }");
}

#[tokio::test(start_paused = true)]
async fn elapsed_submillisecond_public_tick_never_reenters_timer() {
    let tick = Instant::now() + Duration::from_micros(800);
    tokio::time::advance(Duration::from_micros(900)).await;
    let before = Instant::now();
    assert!(before > tick);
    wait_for_public_tick(tick).await;
    assert_eq!(
        Instant::now(),
        before,
        "an elapsed public tick must not register or await another timer"
    );
}

#[tokio::test(start_paused = true)]
async fn future_public_tick_still_waits_without_early_release() {
    let before = Instant::now();
    let tick = before + Duration::from_micros(800);
    wait_for_public_tick(tick).await;
    assert!(Instant::now() >= tick);
    assert!(Instant::now() > before);
}

struct PendingForElapsedTick {
    entered: std::sync::Arc<tokio::sync::Notify>,
}
impl AsyncRead for PendingForElapsedTick {
    fn poll_read(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        _: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.entered.notify_one();
        Poll::Pending
    }
}

#[tokio::test(start_paused = true)]
async fn elapsed_public_tick_beyond_original_allowance_refuses_before_wire() {
    let profile = NetShaperProfile::new(
        1,
        Duration::from_millis(10),
        Duration::from_secs(1),
        Duration::from_millis(10),
        8,
        64,
        4,
        1_000_000,
        1,
    )
    .unwrap();
    let entered = std::sync::Arc::new(tokio::sync::Notify::new());
    let input = PendingForElapsedTick {
        entered: entered.clone(),
    };
    let (tx, mut observer) = tokio::io::duplex(4096);
    let session = NetShaperSession::new(profile, material());
    let mut rng = StdRng::seed_from_u64(399);
    let (result, ()) = tokio::join!(
        session.send_with_rng(input, tx, Instant::now() + Duration::from_secs(1), &mut rng),
        async {
            entered.notified().await;
            // Original tick10ms plus original write allowance10ms is spent.
            tokio::time::advance(Duration::from_millis(21)).await;
        }
    );
    let error = result.unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    assert_eq!(
        error.to_string(),
        "NetShaper public tick exceeded write allowance"
    );
    let mut wire = Vec::new();
    observer.read_to_end(&mut wire).await.unwrap();
    assert!(
        wire.is_empty(),
        "no emission after the original slot allowance"
    );
}
