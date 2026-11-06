use super::*;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpSocket};

/// Exercise the public strategy on real TCP, including ordinary receive EOF.
/// A small requested send buffer exercises constrained canonical delivery;
/// it does not prove a particular native short-write count.
async fn exchange_canonical_buffer(data: Vec<u8>, sni: Option<(usize, usize)>) {
    tokio::time::timeout(Duration::from_secs(10), async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let destination = listener.local_addr().unwrap();
        let socket = TcpSocket::new_v4().unwrap();
        socket.set_send_buffer_size(4096).unwrap();
        let (mut sender, accepted) =
            tokio::try_join!(socket.connect(destination), listener.accept()).unwrap();
        let (mut receiver, _) = accepted;
        let context = super::super::SendFirstContext {
            dst: destination,
            reference_path_hops: None,
        };
        let strategy = OobDataStrategy;
        assert_eq!(strategy.id(), "oob_data");
        let (sent, received) = tokio::join!(
            async {
                let sent = strategy.send_first(&mut sender, &data, sni, &context).await;
                let closed = sender.shutdown().await;
                sent?;
                closed
            },
            async {
                let mut received = Vec::new();
                receiver.read_to_end(&mut received).await?;
                std::io::Result::Ok(received)
            }
        );
        sent.expect("the complete first buffer must finish writing");
        let received = received.unwrap();
        assert!(
            received == data,
            "ordinary TCP bytes differ; expected_len={} received_len={}",
            data.len(),
            received.len()
        );
    })
    .await
    .expect("owned TCP exchange exceeded its 10-second bound");
}

#[tokio::test]
async fn oob_plain_http_preserves_the_complete_request() {
    exchange_canonical_buffer(
        b"GET /owned HTTP/1.1\r\nHost: owned.test\r\nConnection: close\r\n\r\n".to_vec(),
        None,
    )
    .await;
}

#[tokio::test]
async fn oob_single_byte_preserves_the_only_application_byte() {
    exchange_canonical_buffer(vec![b'G'], None).await;
}

#[tokio::test]
async fn oob_backpressure_preserves_all_bytes_and_completes() {
    let data = (0..256 * 1024).map(|index| (index % 251) as u8).collect();
    exchange_canonical_buffer(data, None).await;
}

#[tokio::test]
async fn oob_empty_buffer_keeps_ordinary_eof() {
    exchange_canonical_buffer(Vec::new(), None).await;
}

#[tokio::test]
async fn oob_sni_present_branch_keeps_the_existing_ordinary_buffer() {
    // This preserves the existing branch contract; it is not a TLS handshake.
    exchange_canonical_buffer(b"owned-sni-present-control".to_vec(), Some((6, 3))).await;
}
