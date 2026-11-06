use super::*;
use crate::traffic_privacy::idle_receive_gate_support as gate_support;
use tokio::time::timeout;

async fn pair_gated() -> (LiuStream, LiuStream, gate_support::Gate) {
    let (left, right) = tokio::io::duplex(2048);
    let (right, gate) = gate_support::Gate::wrap(right);
    let original = Instant::now() + Duration::from_secs(3);
    let p = prepared().await;
    let q = prepared().await;
    let a =
        attach_authenticated(left, p, context(), Zeroizing::new([7; 32]), true, original).unwrap();
    let b = attach_authenticated(
        right,
        q,
        context(),
        Zeroizing::new([7; 32]),
        false,
        original,
    )
    .unwrap();
    (a, b, gate)
}

async fn abort_and_join_pair(mut a: LiuStream, mut b: LiuStream) {
    let a_worker = a.worker.take();
    let b_worker = b.worker.take();
    for worker in [&a_worker, &b_worker].into_iter().flatten() {
        worker.abort();
    }
    if let Some(worker) = a_worker {
        let _ = worker.await;
    }
    if let Some(worker) = b_worker {
        let _ = worker.await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn first_byte_keeps_one_record_cutoff_and_canonical_delivery() {
    gate_support::wall_bounded(async {
        let interval = Duration::from_millis(u64::from(settings().io_timeout_ms));
        let (mut a, mut b, gate) = pair_gated().await;
        a.write_all(b"a").await.unwrap();
        b.write_all(b"b").await.unwrap();
        timeout(interval / 2, gate.wait_consumed(1)).await.unwrap();
        assert_eq!(
            gate.consumed(),
            1,
            "gate must observe the actual first byte"
        );
        tokio::time::sleep(interval / 4).await;
        gate.release(usize::MAX);
        let mut received_a = [0; 1];
        let mut received_b = [0; 1];
        a.read_exact(&mut received_a).await.unwrap();
        b.read_exact(&mut received_b).await.unwrap();
        assert_eq!(&received_a, b"b");
        assert_eq!(&received_b, b"a");
        let record_len = gate.consumed();
        let minimum_record_len = HEADER + 1 + DIGEST;
        assert!(record_len > 2);
        let (a_end, b_end) = tokio::join!(a.finish(), b.finish());
        for stats in [a_end.unwrap(), b_end.unwrap()] {
            assert_eq!(stats.sent.data_bytes, 1);
            assert_eq!(stats.received.data_bytes, 1);
        }

        // All bytes below are produced by the same canonical paired sender.
        // The three stops cover initial prefix, middle/body and final trailer.
        // Cover's middle is opaque wire output, not a parser field attribution.
        for stop in [1, HEADER, minimum_record_len - 1] {
            let (mut a, mut b, gate) = pair_gated().await;
            a.write_all(b"a").await.unwrap();
            b.write_all(b"b").await.unwrap();
            timeout(interval / 2, gate.wait_consumed(1)).await.unwrap();
            let first_at = Instant::now();
            let mut healthy = [0; 1];
            a.read_exact(&mut healthy).await.unwrap();
            assert_eq!(&healthy, b"b");
            tokio::time::sleep(interval * 2 / 3).await;
            gate.release(stop - 1);
            timeout(interval / 6, gate.wait_consumed(stop))
                .await
                .unwrap();
            assert_eq!(gate.consumed(), stop);
            let mut withheld = [0xA5; 1];
            let read = async {
                let result = b.read(&mut withheld).await;
                (result, first_at.elapsed())
            };
            let trickle = async {
                for _ in 0..4 {
                    tokio::time::sleep(interval / 3).await;
                    gate.release(1);
                }
            };
            let ((result, elapsed), ()) = tokio::join!(read, trickle);
            let kind = result.as_ref().err().map(io::Error::kind);
            // Join the real owned codec workers before any assertion can panic.
            abort_and_join_pair(a, b).await;
            assert_eq!(kind, Some(io::ErrorKind::TimedOut));
            assert_eq!(withheld, [0xA5], "no unverified application byte");
            assert!(
                elapsed <= interval + interval / 2,
                "record cutoff renewed: {elapsed:?}"
            );
            assert!(gate.consumed() <= stop + 2);
        }
    })
    .await;
}

fn settings() -> LiuSettings {
    LiuSettings {
        class_weights: vec![1, 3],
        client_to_server_counts: vec![vec![3, 1], vec![1, 3]],
        server_to_client_counts: vec![vec![3, 1], vec![1, 3]],
        target_classes: vec![ClassMapping {
            host: "target.test".into(),
            port: 443,
            transport: TrafficTransport::Tcp,
            class: 0,
        }],
        unmatched_traffic_class: Some(1),
        policy_ack_class: 1,
        distortion_microunits: 125_000,
        optimizer_iterations: 2000,
        optimizer_gap_millibits: 1,
        optimizer_timeout_ms: 3000,
        buffer_bytes: 1024,
        wire_batch_bytes: 1024,
        max_wire_bytes: 100_000,
        io_timeout_ms: 300,
        session_timeout_ms: 3000,
        max_queue_delay_ms: 400_000,
    }
}
fn context() -> BoundContext {
    settings()
        .traffic_context("target.test", 443, crate::secure_channel::Transport::Tcp)
        .unwrap()
}
async fn prepared() -> PreparedChannel {
    prepare(settings(), Instant::now() + Duration::from_secs(3))
        .await
        .unwrap()
}

async fn pair_idle() -> (LiuStream, LiuStream, Instant) {
    let original = Instant::now() + Duration::from_millis(3000);
    let (left, right) = tokio::io::duplex(2048);
    let p = prepared().await;
    let a =
        attach_authenticated(left, p, context(), Zeroizing::new([7; 32]), true, original).unwrap();
    let b = attach_authenticated(
        right,
        prepared().await,
        context(),
        Zeroizing::new([7; 32]),
        false,
        original,
    )
    .unwrap();
    (a, b, original)
}

#[tokio::test]
async fn paired_idle_before_first_record_preserves_both_directions() {
    timeout(Duration::from_secs(10), async {
        let (mut a, mut b, _) = pair_idle().await;
        tokio::time::sleep(Duration::from_millis(350)).await;
        let x = async {
            a.write_all(b"left").await?;
            let mut z = [0; 5];
            a.read_exact(&mut z).await?;
            io::Result::Ok(z)
        };
        let y = async {
            b.write_all(b"right").await?;
            let mut z = [0; 4];
            b.read_exact(&mut z).await?;
            io::Result::Ok(z)
        };
        let (x, y) = tokio::join!(x, y);
        assert_eq!(&x.unwrap(), b"right");
        assert_eq!(&y.unwrap(), b"left");
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn paired_idle_between_verified_records_preserves_sequence() {
    timeout(Duration::from_secs(10), async {
        let (mut a, mut b, _) = pair_idle().await;
        let first_a = async {
            a.write_all(b"aaa").await?;
            let mut z = [0; 3];
            a.read_exact(&mut z).await?;
            io::Result::Ok(z)
        };
        let first_b = async {
            b.write_all(b"bbb").await?;
            let mut z = [0; 3];
            b.read_exact(&mut z).await?;
            io::Result::Ok(z)
        };
        let (x, y) = tokio::join!(first_a, first_b);
        assert_eq!(&x.unwrap(), b"bbb");
        assert_eq!(&y.unwrap(), b"aaa");
        tokio::time::sleep(Duration::from_millis(350)).await;
        let second_a = async {
            a.write_all(b"ccc").await?;
            let mut z = [0; 3];
            a.read_exact(&mut z).await?;
            io::Result::Ok(z)
        };
        let second_b = async {
            b.write_all(b"ddd").await?;
            let mut z = [0; 3];
            b.read_exact(&mut z).await?;
            io::Result::Ok(z)
        };
        let (x, y) = tokio::join!(second_a, second_b);
        assert_eq!(&x.unwrap(), b"ddd");
        assert_eq!(&y.unwrap(), b"ccc");
    })
    .await
    .unwrap();
}
