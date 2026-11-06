use super::*;
use crate::phase_witness::ServerPhaseWitness;
use std::future::Future;
use std::task::Poll;
use std::time::Duration;
struct AbortTask(tokio::task::AbortHandle);
impl Drop for AbortTask {
    fn drop(&mut self) {
        self.0.abort();
    }
}

#[tokio::test]
async fn actual_accept_pending_cancel_request_and_peer_close_are_separate_observations() {
    tokio::time::timeout(Duration::from_secs(3), async {
        let (local, remote) = tokio::io::duplex(16 * 1024);
        let (mut client, connection) = h2::client::handshake(local).await.unwrap();
        let driver = tokio::spawn(connection);
        let _owner = AbortTask(driver.abort_handle());
        let witness = ServerPhaseWitness::default();
        let mut server = h2::server::handshake(witness.observe_io(remote))
            .await
            .unwrap();
        {
            let mut accept = Box::pin(accept_h2(&mut server, Some(&witness)));
            assert!(
                std::future::poll_fn(|cx| Poll::Ready(accept.as_mut().poll(cx).is_pending())).await
            );
        }
        let snapshot = witness.transport_snapshot();
        assert!(snapshot.h2_accept.polls > 0 && snapshot.h2_accept.pending > 0);
        assert_eq!(snapshot.h2_accept.cancelled, 1);
        assert_eq!(snapshot.h2_accept.requests, 0);
        let request = http::Request::builder()
            .uri("https://private-marker.test/PRIVATE-PATH")
            .body(())
            .unwrap();
        let (response, _) = client.send_request(request, true).unwrap();
        let (request, mut respond) = accept_h2(&mut server, Some(&witness))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(request.uri().path(), "/PRIVATE-PATH");
        let display = format!("{:?}", witness.transport_snapshot());
        assert!(!display.contains("PRIVATE-PATH") && !display.contains("private-marker"));
        assert_eq!(witness.transport_snapshot().h2_accept.requests, 1);
        respond
            .send_response(Response::builder().status(200).body(()).unwrap(), true)
            .unwrap();
        // Drive server's actual H2 flush concurrently with the response reader.
        let mut next = Box::pin(accept_h2(&mut server, Some(&witness)));
        tokio::select! {
            result = response => assert_eq!(result.unwrap().status(), 200),
            result = &mut next => panic!("unexpected early accept terminal: {}", result.is_none()),
        }
        drop(next);
        driver.abort();
        assert!(driver.await.unwrap_err().is_cancelled());
        drop(client);
        let terminal = accept_h2(&mut server, Some(&witness)).await;
        let snapshot = witness.transport_snapshot();
        match terminal {
            None => assert_eq!(snapshot.h2_accept.eof, 1),
            Some(Err(_)) => assert_eq!(snapshot.h2_accept.errors, 1),
            Some(Ok(_)) => panic!("no extra request was sent"),
        }
        assert!(snapshot.tls_application_io.read_bytes > 0);
        assert!(snapshot.tls_application_io.write_bytes > 0);
    })
    .await
    .unwrap();
}
