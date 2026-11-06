use super::*;
use rand::{CryptoRng, RngCore};
use std::{
    pin::Pin,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    task::{Context, Poll},
};
use tokio::io::{duplex, AsyncReadExt, AsyncWrite};

struct Draws {
    draw: u64,
    calls: usize,
    fail_at: Option<usize>,
}
impl Draws {
    fn truthful() -> Self {
        Self {
            draw: 0,
            calls: 0,
            fail_at: None,
        }
    }
}
impl RngCore for Draws {
    fn next_u32(&mut self) -> u32 {
        panic!("only fallible entropy allowed")
    }
    fn next_u64(&mut self) -> u64 {
        panic!("only fallible entropy allowed")
    }
    fn fill_bytes(&mut self, _: &mut [u8]) {
        panic!("only fallible entropy allowed")
    }
    fn try_fill_bytes(&mut self, bytes: &mut [u8]) -> Result<(), rand::Error> {
        let fail = self.fail_at == Some(self.calls);
        self.calls += 1;
        if fail {
            return Err(rand::Error::new(io::Error::other(
                "controlled entropy failure",
            )));
        }
        assert_eq!(bytes.len(), 8);
        bytes.copy_from_slice(&self.draw.to_le_bytes());
        Ok(())
    }
}
impl CryptoRng for Draws {}
fn profile(slots: usize) -> ScheduleProfile {
    ScheduleProfile::new(
        slots,
        16,
        Duration::from_millis(2),
        Duration::from_millis(40),
        3,
        1,
        3u128.pow(slots as u32),
        1,
    )
    .unwrap()
}
fn batch(p: ScheduleProfile) -> ScheduleBatch {
    ScheduleBatch::new(
        p,
        BatchMaterial::from_preprovisioned(Zeroizing::new([7; 32]), [9; 8]),
    )
    .unwrap()
}
fn cells(values: &[&[u8]]) -> Vec<Zeroizing<Vec<u8>>> {
    values.iter().map(|v| Zeroizing::new(v.to_vec())).collect()
}

#[test]
fn complete_public_budget_is_admitted_without_live_spending_or_entropy() {
    assert!(ScheduleProfile::new(
        3,
        16,
        Duration::from_millis(1),
        Duration::from_secs(1),
        3,
        1,
        9,
        1
    )
    .is_err());
    for (slots, cap, cadence) in [
        (0, 16, 1),
        (65, 16, 1),
        (2, 257, 1),
        (64, 16, 1000),
        (1, 16, 0),
    ] {
        assert!(ScheduleProfile::new(
            slots,
            cap,
            Duration::from_millis(cadence),
            Duration::from_secs(1),
            1,
            1,
            1,
            1
        )
        .is_err());
    }
    // Admission covers precisely the public horizon that real release can
    // afford, including equal odds and unreduced fractions.
    for a in 1..=5 {
        for b in 1..=a {
            for slots in 1..=8 {
                for limit in [1, 3, 9, 81, 65_536] {
                    let p = ScheduleProfile::new(
                        slots,
                        16,
                        Duration::from_millis(1),
                        Duration::from_secs(1),
                        a,
                        b,
                        limit,
                        1,
                    );
                    let mut actual = ScheduleAccountant::new(a, b, limit, 1, slots).unwrap();
                    let possible = (0..slots).all(|_| {
                        actual
                            .release(
                                0,
                                &mut Draws {
                                    draw: u64::MAX,
                                    ..Draws::truthful()
                                },
                            )
                            .is_ok()
                    });
                    assert_eq!(p.is_ok(), possible);
                    if let Ok(p) = p {
                        assert_eq!(batch(p).accountant.receipt().releases, 0);
                    }
                }
            }
        }
    }
}

#[tokio::test]
async fn real_tcp_dummy_data_decoder_and_fixed_horizon() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let p = profile(3);
    let receiver = tokio::spawn({
        let p = p.clone();
        async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            batch(p).receive(&mut socket).await.unwrap()
        }
    });
    let mut socket = tokio::net::TcpStream::connect(address).await.unwrap();
    let started = Instant::now();
    let sent = batch(p.clone())
        .send(
            cells(&[b"", b"hello", b"world"]),
            &mut Draws::truthful(),
            &mut socket,
        )
        .await
        .unwrap();
    assert!(started.elapsed() >= p.horizon());
    let received = receiver.await.unwrap();
    assert_eq!(received.released_bits, [0, 1, 1]);
    assert_eq!(
        received
            .payloads
            .iter()
            .map(|v| v.as_slice())
            .collect::<Vec<_>>(),
        [b"".as_slice(), b"hello", b"world"]
    );
    assert_eq!(
        received.wire_bytes,
        p.frame_bytes(0).unwrap() + 2 * p.frame_bytes(1).unwrap()
    );
    assert_eq!(sent.fully_written_frame_bytes, received.wire_bytes);
    assert_eq!(sent.accounting.releases, 3);
    assert_eq!(sent.accounting.odds_numerator, "27");
}

#[tokio::test]
async fn invalid_cell_count_or_size_refuses_before_budget_and_wire() {
    for input in [
        cells(&[b"one"]),
        cells(&[b"this payload exceeds sixteen bytes", b""]),
    ] {
        let mut sink = Vec::new();
        let failure = batch(profile(2))
            .send(input, &mut Draws::truthful(), &mut sink)
            .await
            .unwrap_err();
        assert_eq!(failure.kind, io::ErrorKind::InvalidInput);
        assert_eq!(failure.receipt.accounting.releases, 0);
        assert!(!failure.partial_frame_may_have_been_written);
        assert!(sink.is_empty());
    }
}

#[tokio::test]
async fn initial_entropy_failure_has_no_prefix_and_retains_actual_spend() {
    let mut rng = Draws {
        fail_at: Some(0),
        ..Draws::truthful()
    };
    let mut sink = Vec::new();
    let failure = batch(profile(2))
        .send(cells(&[b"secret", b""]), &mut rng, &mut sink)
        .await
        .unwrap_err();
    assert!(sink.is_empty());
    assert_eq!(failure.receipt.accounting.releases, 1);
    assert_eq!(failure.receipt.accounting.odds_numerator, "3");
    assert_eq!(failure.receipt.fully_written_slots, 0);
    assert!(!failure.partial_frame_may_have_been_written);
}

#[tokio::test]
async fn later_entropy_failure_does_not_reset_already_spent_budget() {
    let mut rng = Draws {
        fail_at: Some(2),
        ..Draws::truthful()
    };
    let mut sink = Vec::new();
    let p = profile(3);
    let failure = batch(p.clone())
        .send(cells(&[b"", b"data", b"last"]), &mut rng, &mut sink)
        .await
        .unwrap_err();
    assert_eq!(failure.receipt.accounting.releases, 3);
    assert_eq!(failure.receipt.accounting.odds_numerator, "27");
    assert_eq!(failure.receipt.fully_written_slots, 2);
    assert_eq!(
        sink.len(),
        p.frame_bytes(0).unwrap() + p.frame_bytes(1).unwrap()
    );
    assert_eq!(failure.receipt.fully_written_frame_bytes, sink.len());
}

#[tokio::test]
async fn chosen_wire_size_does_not_use_secret_payload_length_or_dummy_fallback() {
    let p = profile(1);
    for payload in [b"".as_slice(), b"x", b"0123456789abcdef"] {
        let mut rng = Draws {
            draw: if payload.is_empty() { 3 } else { 0 },
            ..Draws::truthful()
        };
        let mut sink = Vec::new();
        batch(p.clone())
            .send(cells(&[payload]), &mut rng, &mut sink)
            .await
            .unwrap();
        assert_eq!(sink[0], 1);
        assert_eq!(sink.len(), p.frame_bytes(1).unwrap());
        let got = batch(p.clone())
            .receive(&mut sink.as_slice())
            .await
            .unwrap();
        assert_eq!(got.payloads[0].as_slice(), payload);
    }
}

async fn encoded(p: &ScheduleProfile) -> Vec<u8> {
    let mut output = Vec::new();
    batch(p.clone())
        .send(
            cells(&[b"one", b"two"]),
            &mut Draws::truthful(),
            &mut output,
        )
        .await
        .unwrap();
    output
}
#[tokio::test]
async fn auth_binds_order_bits_profile_padding_key_and_complete_batch() {
    let p = profile(2);
    let good = encoded(&p).await;
    let frame_size = p.frame_bytes(1).unwrap();
    let mut corrupt_tag = good.clone();
    corrupt_tag[20] ^= 1;
    let mut corrupt_padding = good.clone();
    corrupt_padding[frame_size - 1] = 1;
    let mut invalid_bit = good.clone();
    invalid_bit[0] = 2;
    let mut flipped_bit = good.clone();
    flipped_bit[0] = 0;
    let mut reordered = good[frame_size..].to_vec();
    reordered.extend_from_slice(&good[..frame_size]);
    for bytes in [
        corrupt_tag,
        corrupt_padding,
        invalid_bit,
        flipped_bit,
        reordered,
        good[..good.len() - 1].to_vec(),
        good[..frame_size].to_vec(),
    ] {
        assert!(batch(p.clone())
            .receive(&mut bytes.as_slice())
            .await
            .is_err());
    }
    let wrong = ScheduleBatch::new(
        p.clone(),
        BatchMaterial::from_preprovisioned(Zeroizing::new([8; 32]), [9; 8]),
    )
    .unwrap();
    assert!(wrong.receive(&mut good.as_slice()).await.is_err());
    let other = ScheduleProfile::new(
        2,
        16,
        Duration::from_millis(3),
        Duration::from_millis(40),
        3,
        1,
        9,
        1,
    )
    .unwrap();
    assert!(batch(other).receive(&mut good.as_slice()).await.is_err());
    let mut extra = good.clone();
    extra.extend_from_slice(b"later");
    let mut reader = extra.as_slice();
    batch(p).receive(&mut reader).await.unwrap();
    assert_eq!(reader, b"later");
}

#[tokio::test]
async fn bounded_real_backpressure_returns_partial_failure_and_spending() {
    let p = ScheduleProfile::new(
        2,
        16,
        Duration::from_millis(2),
        Duration::from_millis(5),
        3,
        1,
        9,
        1,
    )
    .unwrap();
    let (mut writer, mut reader) = duplex(1);
    let started = Instant::now();
    let failure = batch(p)
        .send(cells(&[b"data", b""]), &mut Draws::truthful(), &mut writer)
        .await
        .unwrap_err();
    assert_eq!(failure.kind, io::ErrorKind::TimedOut);
    assert_eq!(failure.receipt.accounting.releases, 1);
    assert_eq!(failure.receipt.fully_written_slots, 0);
    assert!(failure.partial_frame_may_have_been_written);
    assert!(started.elapsed() < Duration::from_secs(1));
    assert_eq!(reader.read_u8().await.unwrap(), 1);
    drop(writer);
    assert!(reader.read_u8().await.is_err());
}

#[tokio::test]
async fn receiver_idle_deadline_and_truncated_data_never_return_partial_batch() {
    let p = ScheduleProfile::new(
        2,
        16,
        Duration::from_millis(2),
        Duration::from_millis(5),
        3,
        1,
        9,
        1,
    )
    .unwrap();
    let (_held, mut reader) = duplex(1);
    let failure = batch(p).receive(&mut reader).await.err().unwrap();
    assert_eq!(failure.kind(), io::ErrorKind::TimedOut);
}

struct OwnedSink {
    stream: tokio::io::DuplexStream,
    dropped: Arc<AtomicBool>,
}
impl Drop for OwnedSink {
    fn drop(&mut self) {
        self.dropped.store(true, Ordering::SeqCst);
    }
}
impl AsyncWrite for OwnedSink {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write(cx, bytes)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}
#[tokio::test]
async fn cancellation_drops_owned_one_shot_sender_and_owner_stream() {
    let (stream, mut reader) = duplex(1);
    let dropped = Arc::new(AtomicBool::new(false));
    let mut wire = OwnedSink {
        stream,
        dropped: dropped.clone(),
    };
    let task = tokio::spawn(async move {
        batch(profile(2))
            .send(cells(&[b"data", b""]), &mut Draws::truthful(), &mut wire)
            .await
    });
    // A received byte proves the task entered its real partial write.
    assert_eq!(reader.read_u8().await.unwrap(), 1);
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    assert!(dropped.load(Ordering::SeqCst));
    let mut remaining = Vec::new();
    reader.read_to_end(&mut remaining).await.unwrap();
    assert!(remaining.len() <= 1);
    // Zeroization follows the consumed key/prefix/plaintext Zeroizing owners;
    // this test observes owner teardown, not allocator-residue inspection.
}

#[tokio::test(start_paused = true)]
async fn public_horizon_does_not_stop_on_secret_empty_cells() {
    for values in [cells(&[b"", b"", b""]), cells(&[b"a", b"b", b"c"])] {
        let p = profile(3);
        let start = Instant::now();
        let mut sink = Vec::new();
        let receipt = batch(p.clone())
            .send(values, &mut Draws::truthful(), &mut sink)
            .await
            .unwrap();
        assert_eq!(start.elapsed(), p.horizon());
        assert_eq!(receipt.fully_written_slots, 3);
        assert_eq!(receipt.accounting.releases, 3);
    }
}
