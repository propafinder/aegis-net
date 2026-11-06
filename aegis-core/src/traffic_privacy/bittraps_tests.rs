use super::*;
use rand::{rngs::StdRng, SeedableRng};
fn profile(slots: u32) -> BitTrapsConfig {
    BitTrapsConfig::new(
        slots,
        Duration::from_millis(100),
        Duration::from_millis(50),
        64,
        vec![(8, 1), (16, 1)],
    )
    .unwrap()
}
fn material(seed: u8) -> BitTrapsMaterial {
    BitTrapsMaterial::from_preprovisioned(Zeroizing::new([seed; 32]))
}
#[test]
fn profile_bounds_and_canonical_distribution_refuse() {
    let ms = Duration::from_millis(1);
    for service in [
        vec![],
        vec![(1, 0)],
        vec![(2, 1), (1, 1)],
        vec![(1, u32::MAX), (2, 1)],
        vec![(65536, 1)],
    ] {
        assert!(BitTrapsConfig::new(2, ms, ms, 16, service).is_err());
    }
    assert!(BitTrapsConfig::new(257, ms, ms, 16, vec![(1, 1)]).is_err());
    assert!(BitTrapsConfig::new(1, ms, ms * 2, 16, vec![(1, 1)]).is_err());
    assert!(BitTrapsConfig::new(1, ms, ms, 0, vec![(1, 1)]).is_err());
    assert_eq!(profile(4).worst_wire_bytes(), 4 * (16 + 24));
}
#[test]
fn serde_eq_rebinds_full_descriptor_and_revalidates() {
    let p = profile(3);
    let round: BitTrapsConfig = serde_json::from_slice(&serde_json::to_vec(&p).unwrap()).unwrap();
    assert_eq!(p, round);
    let mut v = serde_json::to_value(&p).unwrap();
    v["slots"] = 0.into();
    assert!(serde_json::from_value::<BitTrapsConfig>(v).is_err());
    let mut v = serde_json::to_value(&p).unwrap();
    v["descriptor"] = true.into();
    assert!(serde_json::from_value::<BitTrapsConfig>(v).is_err());
    assert_ne!(p.descriptor_sha256(), profile(2).descriptor_sha256());
}
#[test]
fn queue_real_padding_and_overflow_preserve_fifo() {
    let mut q = SecretQueue::new(5);
    q.enqueue(b"abcde").unwrap();
    assert!(q.enqueue(b"f").is_err());
    let a = q.frame(3);
    assert_eq!(&a[4..], b"abc");
    let b = q.frame(4);
    assert_eq!(&b[4..6], b"de");
    assert_eq!(&b[6..], &[0, 0]);
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
        Err(rand::Error::new(io::Error::other("controlled refusal")))
    }
}
impl CryptoRng for Broken {}
#[test]
fn independent_service_distribution_and_entropy_refusal() {
    let p = profile(2);
    let mut rng = StdRng::seed_from_u64(29);
    let mut counts = [0; 2];
    for _ in 0..4096 {
        let n = p
            .sample(&mut rng, Instant::now() + Duration::from_secs(1))
            .unwrap();
        counts[usize::from(n == 16)] += 1;
    }
    assert!(counts.iter().all(|n| *n > 1800 && *n < 2300));
    assert!(p
        .sample(&mut Broken, Instant::now() + Duration::from_secs(1))
        .is_err());
    assert_eq!(
        p.sample(&mut rng, Instant::now()).unwrap_err().kind(),
        io::ErrorKind::TimedOut
    );
}
#[tokio::test(start_paused = true)]
async fn actual_sender_keeps_dummy_horizon_after_eof_and_receiver_decodes() {
    let p = profile(3);
    let (mut tx, mut rx) = tokio::io::duplex(4096);
    let end = Instant::now() + Duration::from_secs(2);
    let mut rng = StdRng::seed_from_u64(29);
    let receipt = BitTrapsSession::new(p.clone(), material(1))
        .unwrap()
        .send_with_rng(b"payload".as_slice(), &mut tx, end, &mut rng)
        .await
        .unwrap();
    drop(tx);
    assert!(receipt.input_eof_observed);
    assert_eq!(receipt.pending_bytes, 0);
    assert_eq!(receipt.delivered_input_bytes, 7);
    let mut bytes = Vec::new();
    rx.read_to_end(&mut bytes).await.unwrap();
    assert_eq!(bytes.len() as u64, receipt.wire_bytes);
    assert_eq!(
        BitTrapsSession::new(p, material(1))
            .unwrap()
            .receive(bytes.as_slice(), end)
            .await
            .unwrap()
            .as_slice(),
        b"payload"
    );
    assert_eq!(Instant::now(), end - Duration::from_millis(1700));
}
fn wire(p: &BitTrapsConfig, index: u32, selected: usize, input: &[u8]) -> Vec<u8> {
    let mat = DerivedMaterial::derive(material(3), p).unwrap();
    let cipher = ChaCha20Poly1305::new_from_slice(mat.key.as_ref()).unwrap();
    let mut q = SecretQueue::new(64);
    q.enqueue(input).unwrap();
    let plain = q.frame(selected);
    let c = cipher
        .encrypt(
            mat.nonce(index).as_ref().into(),
            Payload {
                msg: plain.as_ref(),
                aad: &aad(p, index, selected),
            },
        )
        .unwrap();
    let mut b = (selected as u32).to_be_bytes().to_vec();
    b.extend_from_slice(&c);
    b
}
#[tokio::test]
async fn actual_authentication_wrong_slot_profile_tamper_and_partial_refuse() {
    let p = profile(1);
    let good = wire(&p, 0, 8, b"data");
    let end = Instant::now() + Duration::from_secs(2);
    assert_eq!(
        BitTrapsSession::new(p.clone(), material(3))
            .unwrap()
            .receive(good.as_slice(), end)
            .await
            .unwrap()
            .as_slice(),
        b"data"
    );
    let mut altered = good.clone();
    altered[8] ^= 1;
    for b in [
        altered,
        good[..good.len() - 1].to_vec(),
        wire(&p, 1, 8, b"data"),
        wire(&p, 0, 9, b"data"),
    ] {
        assert!(BitTrapsSession::new(p.clone(), material(3))
            .unwrap()
            .receive(b.as_slice(), end)
            .await
            .is_err());
    }
    assert!(BitTrapsSession::new(profile(2), material(3))
        .unwrap()
        .receive(good.as_slice(), end)
        .await
        .is_err());
}
#[tokio::test(start_paused = true)]
async fn stalled_carrier_preserves_original_deadline() {
    let (tx, _held) = tokio::io::duplex(1);
    let end = Instant::now() + Duration::from_secs(1);
    let mut rng = StdRng::seed_from_u64(29);
    let begin = Instant::now();
    assert_eq!(
        BitTrapsSession::new(profile(1), material(1))
            .unwrap()
            .send_with_rng(tokio::io::empty(), tx, end, &mut rng)
            .await
            .unwrap_err()
            .kind(),
        io::ErrorKind::TimedOut
    );
    assert!(Instant::now() - begin < Duration::from_secs(1));
}
#[test]
fn duplex_reflection_and_short_epoch_clock_refuse_before_worker() {
    let (a, _b) = tokio::io::duplex(4096);
    assert!(attach_authenticated(
        a,
        profile(1),
        material(1),
        material(1),
        Instant::now() + Duration::from_secs(1)
    )
    .is_err());
}
#[tokio::test(start_paused = true)]
async fn two_owned_directions_halfclose_and_preserve_exact_payloads() {
    let (a, b) = tokio::io::duplex(4096);
    let end = Instant::now() + Duration::from_secs(2);
    let (mut a, mut b) = (
        attach_authenticated(a, profile(3), material(1), material(2), end).unwrap(),
        attach_authenticated(b, profile(3), material(2), material(1), end).unwrap(),
    );
    let left = async move {
        a.write_all(b"left").await?;
        let (r, w) = tokio::io::split(a);
        let mut r = r;
        let mut w = w;
        let mut out = Vec::new();
        tokio::try_join!(w.shutdown(), r.read_to_end(&mut out))?;
        Ok::<_, io::Error>(out)
    };
    let right = async move {
        b.write_all(b"right").await?;
        let (r, w) = tokio::io::split(b);
        let mut r = r;
        let mut w = w;
        let mut out = Vec::new();
        tokio::try_join!(w.shutdown(), r.read_to_end(&mut out))?;
        Ok::<_, io::Error>(out)
    };
    let (l, r) = tokio::try_join!(left, right).unwrap();
    assert_eq!(l, b"right");
    assert_eq!(r, b"left");
}
#[tokio::test(start_paused = true)]
async fn owned_stream_open_source_cannot_masquerade_as_clean_epoch_eof() {
    let (a, b) = tokio::io::duplex(4096);
    let end = Instant::now() + Duration::from_secs(2);
    let (mut a, _b) = (
        attach_authenticated(a, profile(1), material(1), material(2), end).unwrap(),
        attach_authenticated(b, profile(1), material(2), material(1), end).unwrap(),
    );
    let mut bytes = Vec::new();
    assert_eq!(
        a.read_to_end(&mut bytes).await.unwrap_err().kind(),
        io::ErrorKind::UnexpectedEof
    );
}
#[tokio::test]
async fn dropping_owned_adapter_aborts_transport_not_detached() {
    let (a, mut b) = tokio::io::duplex(4096);
    let stream = attach_authenticated(
        a,
        profile(1),
        material(1),
        material(2),
        Instant::now() + Duration::from_secs(2),
    )
    .unwrap();
    drop(stream);
    tokio::task::yield_now().await;
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(1), b.read_u8())
            .await
            .unwrap()
            .unwrap_err()
            .kind(),
        io::ErrorKind::UnexpectedEof
    );
}
fn markov(padding: bool) -> FiniteStreamModel {
    FiniteStreamModel {
        horizon: 3,
        arrival_sizes: vec![0, 2],
        initial: vec![0.5, 0.5],
        transition: vec![vec![0.8, 0.2], vec![0.2, 0.8]],
        service: vec![(0, 0.5), (2, 0.5)],
        queue_cap: 32,
        padding,
    }
}
#[test]
fn full_markov_joint_law_padding_removes_inner_size_information() {
    let r = finite_stream_law(&markov(true)).unwrap();
    assert_eq!(r.enumerated_paths, 64);
    assert!((r.probability_mass - 1.0).abs() < 1e-10);
    assert!(r.joint_sequence_mutual_information_bits < 1e-12);
    assert!(r.expected_padding_bytes > 0.0);
    assert!(r.expected_tail_bytes > 0.0);
    let bare = finite_stream_law(&markov(false)).unwrap();
    assert!(bare.joint_sequence_mutual_information_bits > 0.1);
    assert_eq!(bare.expected_padding_bytes, 0.0);
}
#[test]
fn observable_overflow_is_retained_as_sequence_information() {
    let mut m = markov(true);
    m.queue_cap = 1;
    let r = finite_stream_law(&m).unwrap();
    assert!(r.overflow_probability > 0.0);
    assert!(r.joint_sequence_mutual_information_bits > 0.1);
}
#[test]
fn finite_grid_optimizer_respects_padding_queue_tail_and_refusal_costs() {
    let mut base = markov(true);
    base.queue_cap = 32;
    let grid = vec![vec![(0, 1.0)], vec![(2, 1.0)], vec![(4, 1.0)]];
    let (i, r) = optimize_service_grid(&base, &grid, 10.0, 10.0, 0.0).unwrap();
    assert_eq!(i, 1);
    assert_eq!(r.expected_tail_bytes, 0.0);
    assert!(r.joint_sequence_mutual_information_bits < 1e-12);
    assert!(optimize_service_grid(&base, &grid, 0.0, 0.0, 0.0).is_err());
}
#[test]
fn finite_state_model_invalid_mass_unbounded_paths_refuse() {
    let mut m = markov(true);
    m.initial = vec![0.4, 0.4];
    assert!(finite_stream_law(&m).is_err());
    let mut m = markov(true);
    m.horizon = 7;
    assert!(finite_stream_law(&m).is_err());
    let mut m = markov(true);
    m.transition[0][0] = f64::NAN;
    assert!(finite_stream_law(&m).is_err());
}

#[tokio::test(start_paused = true)]
async fn actual_wire_service_sequence_is_independent_of_input_and_dummy_padding() {
    async fn capture(input: &[u8], seed: u8) -> (Vec<usize>, BitTrapsReceipt) {
        let (tx, mut rx) = tokio::io::duplex(4096);
        let mut rng = StdRng::seed_from_u64(733);
        let receipt = BitTrapsSession::new(profile(3), material(seed))
            .unwrap()
            .send_with_rng(input, tx, Instant::now() + Duration::from_secs(2), &mut rng)
            .await
            .unwrap();
        let mut wire = Vec::new();
        rx.read_to_end(&mut wire).await.unwrap();
        let mut selected = Vec::new();
        let mut pos = 0;
        while pos < wire.len() {
            let n = u32::from_be_bytes(wire[pos..pos + 4].try_into().unwrap()) as usize;
            selected.push(n);
            pos += n + OVERHEAD;
        }
        assert_eq!(pos, wire.len());
        (selected, receipt)
    }
    let (a, ra) = capture(b"a", 11).await;
    let (b, rb) = capture(b"seventeen-byte-da", 12).await;
    assert_eq!(a, b);
    assert_eq!(a.len(), 3);
    assert_ne!(ra.padding_bytes, rb.padding_bytes);
    assert_eq!(ra.pending_bytes, 0);
    assert_eq!(rb.pending_bytes, 0);
}
#[tokio::test(start_paused = true)]
async fn entropy_refuses_before_any_application_read_or_wire_output() {
    struct Observed(std::sync::Arc<std::sync::atomic::AtomicUsize>);
    impl AsyncRead for Observed {
        fn poll_read(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
            _: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<io::Result<()>> {
            self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            std::task::Poll::Ready(Ok(()))
        }
    }
    let reads = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let (tx, mut rx) = tokio::io::duplex(4096);
    assert!(BitTrapsSession::new(profile(2), material(1))
        .unwrap()
        .send_with_rng(
            Observed(reads.clone()),
            tx,
            Instant::now() + Duration::from_secs(2),
            &mut Broken
        )
        .await
        .is_err());
    assert_eq!(reads.load(std::sync::atomic::Ordering::SeqCst), 0);
    let mut out = Vec::new();
    rx.read_to_end(&mut out).await.unwrap();
    assert!(out.is_empty());
}
#[tokio::test(start_paused = true)]
async fn owned_stream_authenticated_dummy_does_not_hide_real_unserved_tail() {
    let p = BitTrapsConfig::new(
        2,
        Duration::from_millis(100),
        Duration::from_millis(50),
        64,
        vec![(0, 1)],
    )
    .unwrap();
    let (a, b) = tokio::io::duplex(4096);
    let end = Instant::now() + Duration::from_secs(2);
    let (mut a, b) = (
        attach_authenticated(a, p.clone(), material(1), material(2), end).unwrap(),
        attach_authenticated(b, p, material(2), material(1), end).unwrap(),
    );
    a.write_all(b"tail").await.unwrap();
    let left = async {
        let mut out = Vec::new();
        let (r, w) = tokio::io::split(a);
        let mut r = r;
        let mut w = w;
        tokio::try_join!(w.shutdown(), r.read_to_end(&mut out))
    };
    let right = async {
        let mut out = Vec::new();
        let (r, w) = tokio::io::split(b);
        let mut r = r;
        let mut w = w;
        tokio::try_join!(w.shutdown(), r.read_to_end(&mut out))
    };
    let (l, _r) = tokio::join!(left, right);
    assert_eq!(l.unwrap_err().kind(), io::ErrorKind::UnexpectedEof);
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

#[test]
fn finite_support_probability_underflow_cannot_hide_reachable_overflow() {
    let m = FiniteStreamModel {
        horizon: 2,
        arrival_sizes: vec![0, 2],
        initial: vec![1.0, 1e-200],
        transition: vec![vec![1.0, 1e-200], vec![1.0, 1e-200]],
        service: vec![(0, 1.0)],
        queue_cap: 2,
        padding: true,
    };
    assert_eq!(
        finite_stream_law(&m).unwrap_err().kind(),
        io::ErrorKind::InvalidData
    );
    assert!(optimize_service_grid(&m, &[vec![(0, 1.0)]], 10.0, 10.0, 10.0).is_err());
}
#[test]
fn finite_joint_mi_uses_logs_when_marginal_product_underflows() {
    let m = FiniteStreamModel {
        horizon: 1,
        arrival_sizes: vec![0, 1],
        initial: vec![1.0, 1e-200],
        transition: vec![vec![1.0, 0.0], vec![1.0, 0.0]],
        service: vec![(1, 1.0)],
        queue_cap: 2,
        padding: false,
    };
    let r = finite_stream_law(&m).unwrap();
    assert!(r.joint_sequence_mutual_information_bits.is_finite());
    assert!(r.joint_sequence_mutual_information_bits > 0.0);
    assert!(!r.overflow_reachable);
}
#[test]
fn representable_tiny_positive_overflow_support_is_a_hard_grid_refusal() {
    let m = FiniteStreamModel {
        horizon: 1,
        arrival_sizes: vec![0, 2],
        initial: vec![1.0, 1e-200],
        transition: vec![vec![1.0, 0.0], vec![1.0, 0.0]],
        service: vec![(0, 1.0)],
        queue_cap: 1,
        padding: true,
    };
    let r = finite_stream_law(&m).unwrap();
    assert!(r.overflow_reachable);
    assert!(r.overflow_probability > 0.0);
    assert!(optimize_service_grid(&m, &[vec![(0, 1.0)]], 10.0, 10.0, 10.0).is_err());
}

#[tokio::test(start_paused = true)]
async fn owned_stream_debug_redacts_actual_buffered_synthetic_application_marker() {
    let (transport, _held) = tokio::io::duplex(4096);
    let mut stream = attach_authenticated(
        transport,
        profile(2),
        material(31),
        material(32),
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
    assert_eq!(public, "BitTrapsStream { .. }");
}

use std::{
    pin::Pin,
    task::{Context, Poll},
};

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
    let p = BitTrapsConfig::new(
        1,
        Duration::from_millis(10),
        Duration::from_millis(10),
        8,
        vec![(8, 1)],
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
    let receipt = BitTrapsSession::new(p, material(1))
        .unwrap()
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
    assert_eq!(receipt.delivered_input_bytes, 0);
    assert_eq!(receipt.padding_bytes, 8);
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
    let p = BitTrapsConfig::new(
        1,
        Duration::from_millis(10),
        Duration::from_millis(10),
        8,
        vec![(8, 1)],
    )
    .unwrap();
    let (tx, mut rx) = tokio::io::duplex(4096);
    let mut rng = StdRng::seed_from_u64(399);
    let error = BitTrapsSession::new(p, material(1))
        .unwrap()
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
        "BIT-TRAPS input poll exceeded public tick"
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
        profile(1),
        material(1),
        material(2),
        Instant::now() + Duration::from_secs(1),
    )
    .unwrap();
    for _ in 0..2 {
        let error = stream.read_u8().await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::ConnectionReset);
        assert_eq!(error.to_string(), "BIT-TRAPS receiver header failed");
        assert!(!format!("{error:?}").contains("private-application-error-marker"));
    }
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
    let profile = BitTrapsConfig::new(
        1,
        Duration::from_millis(10),
        Duration::from_millis(10),
        8,
        vec![(8, 1)],
    )
    .unwrap();
    let entered = std::sync::Arc::new(tokio::sync::Notify::new());
    let input = PendingForElapsedTick {
        entered: entered.clone(),
    };
    let (tx, mut observer) = tokio::io::duplex(4096);
    let session = BitTrapsSession::new(profile, material(1)).unwrap();
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
        "BIT-TRAPS public tick exceeded write allowance"
    );
    let mut wire = Vec::new();
    observer.read_to_end(&mut wire).await.unwrap();
    assert!(
        wire.is_empty(),
        "no emission after the original slot allowance"
    );
}
