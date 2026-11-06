use super::*;
use std::time::Duration;

struct OwnedTask(tokio::task::JoinHandle<()>);
impl Drop for OwnedTask {
    fn drop(&mut self) {
        self.0.abort();
    }
}
impl OwnedTask {
    async fn stop(mut self) {
        self.0.abort();
        let joined = tokio::time::timeout(Duration::from_secs(2), &mut self.0)
            .await
            .expect("owned H2 task abort is joined");
        if let Err(error) = joined {
            assert!(error.is_cancelled(), "owned H2 task must not panic");
        }
    }
}

async fn read_sequence(raw: Vec<u8>, count: usize) -> Vec<anyhow::Result<Option<Vec<u8>>>> {
    tokio::time::timeout(Duration::from_secs(3), async move {
        let (client_io, server_io) = tokio::io::duplex(4096);
        let (client, server) = tokio::join!(
            h2::client::handshake(client_io),
            h2::server::handshake(server_io)
        );
        let (mut client, connection) = client.expect("synthetic client handshake");
        let client_driver = OwnedTask(tokio::spawn(async move {
            let _ = connection.await;
        }));
        let mut connection = server.expect("synthetic server handshake");
        let (response, mut send) = client
            .send_request(
                http::Request::builder()
                    .uri("https://fixture.invalid/")
                    .body(())
                    .unwrap(),
                false,
            )
            .expect("request");
        send.send_data(Bytes::from(raw), true)
            .expect("bounded request END_STREAM");
        let (request, respond) = connection
            .accept()
            .await
            .expect("one request")
            .expect("valid request");
        let mut recv = request.into_body();
        let server_driver = OwnedTask(tokio::spawn(async move {
            while connection.accept().await.is_some() {}
        }));
        let mut pending = Vec::new();
        let mut results = Vec::new();
        for _ in 0..count {
            results.push(
                read_grpc_message_limited(&mut recv, &mut pending, MAX_GRPC_MESSAGE_BYTES).await,
            );
        }
        drop(recv);
        drop(respond);
        drop(response);
        drop(send);
        drop(client);
        server_driver.stop().await;
        client_driver.stop().await;
        results
    })
    .await
    .expect("owned synthetic H2 framing fixture is bounded")
}

fn frame(payload: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0];
    bytes.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    bytes.extend_from_slice(payload);
    bytes
}
fn invalid(result: &anyhow::Result<Option<Vec<u8>>>) {
    let error = result
        .as_ref()
        .expect_err("incomplete frame must not become clean EOF");
    assert_eq!(
        error
            .downcast_ref::<std::io::Error>()
            .expect("typed framing error")
            .kind(),
        std::io::ErrorKind::InvalidData
    );
    assert_eq!(error.to_string(), "incomplete gRPC message at END_STREAM");
}
#[tokio::test]
async fn actual_reader_clean_end_stream_and_complete_pending_messages() {
    assert!(read_sequence(Vec::new(), 1)
        .await
        .remove(0)
        .unwrap()
        .is_none());
    let mut raw = frame(b"first");
    raw.extend_from_slice(&frame(b""));
    raw.extend_from_slice(&frame(b"last"));
    let mut got = read_sequence(raw, 4).await.into_iter();
    assert_eq!(got.next().unwrap().unwrap(), Some(b"first".to_vec()));
    assert_eq!(got.next().unwrap().unwrap(), Some(Vec::new()));
    assert_eq!(got.next().unwrap().unwrap(), Some(b"last".to_vec()));
    assert!(got.next().unwrap().unwrap().is_none());
}
#[tokio::test]
async fn actual_reader_refuses_partial_header_at_end_stream() {
    let header = frame(b"body");
    for len in 1..5 {
        invalid(&read_sequence(header[..len].to_vec(), 1).await[0]);
    }
}
#[tokio::test]
async fn actual_reader_refuses_partial_body_at_end_stream() {
    let raw = frame(b"body");
    for len in 5..raw.len() {
        invalid(&read_sequence(raw[..len].to_vec(), 1).await[0]);
    }
}
#[tokio::test]
async fn actual_reader_drains_complete_message_before_refusing_partial_suffix() {
    let mut raw = frame(b"complete");
    raw.extend_from_slice(&frame(b"missing")[..7]);
    let got = read_sequence(raw, 2).await;
    assert_eq!(got[0].as_ref().unwrap(), &Some(b"complete".to_vec()));
    invalid(&got[1]);
}
