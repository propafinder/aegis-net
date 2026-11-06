//! Actual legacy-handler decoy and admission-deadline regressions.
//! Fixtures use in-memory streams and synthetic credentials only.
use super::*;
use aegis_core::tunnel::{open_tunnel_response, seal_tunnel_request};
use std::{future::Future, sync::Arc};

const CURRENT: &[u8] = b"synthetic-current-fallback-regression-key";
const LEGACY: &[u8] = b"synthetic-legacy-fallback-regression-key";

struct OwnedTask<T>(tokio::task::JoinHandle<T>);
impl<T> Drop for OwnedTask<T> {
    fn drop(&mut self) {
        self.0.abort();
    }
}

fn synthetic_keyring() -> TunnelAuthKeyring {
    TunnelAuthKeyring {
        keys: vec![
            TunnelAuthKey {
                id: Arc::from("synthetic-current"),
                secret: Arc::from(CURRENT),
                legacy: false,
                not_after_unix_secs: None,
            },
            TunnelAuthKey {
                id: Arc::from("synthetic-legacy"),
                secret: Arc::from(LEGACY),
                legacy: true,
                not_after_unix_secs: Some(u64::MAX),
            },
        ]
        .into(),
        operational_log: Default::default(),
        inner_tls: None,
        https_bridge: None,
        fronted_origin: None,
        relay_training: None,
    }
}

fn header<'a>(head: &'a str, name: &str) -> Option<&'a str> {
    head.split("\r\n").skip(1).find_map(|line| {
        let (key, value) = line.split_once(':')?;
        key.eq_ignore_ascii_case(name).then(|| value.trim())
    })
}

#[tokio::test]
async fn malformed_legacy_close_uses_shared_identity_date_and_generic_400_body() {
    let (mut client, mut server_io) = tokio::io::duplex(8192);
    let mut server = OwnedTask(tokio::spawn(async move {
        handle_legacy_stream_session_with_admission(
            &mut server_io,
            &synthetic_keyring(),
            "close",
            &ServerLimits::default(),
            &TargetPolicyConfig::default(),
            &RateLimiter::new(8, 60, false),
            "192.0.2.10:49001".parse().unwrap(),
            AdmissionBudget::new(Duration::from_secs(2)),
        )
        .await
    }));
    client
        .write_all(&encode_stream_frame(b"malformed-not-sealed"))
        .await
        .unwrap();
    let mut bytes = Vec::new();
    tokio::time::timeout(
        Duration::from_secs(2),
        client.take(8193).read_to_end(&mut bytes),
    )
    .await
    .expect("actual legacy handler closes within original bounded admission")
    .unwrap();
    assert!(
        bytes.len() <= 8192,
        "fixture response capture stays bounded"
    );
    tokio::time::timeout(Duration::from_secs(2), &mut server.0)
        .await
        .unwrap()
        .unwrap()
        .unwrap();

    let response = std::str::from_utf8(&bytes).unwrap();
    let (head, body) = response.split_once("\r\n\r\n").unwrap();
    assert!(head.starts_with("HTTP/1.1 400 Bad Request\r\n"));
    let shared = decoy::pick(0);
    assert_eq!(header(head, "Server"), Some(shared.server));
    // Date absence is a deterministic baseline failure for every deck identity.
    let date = header(head, "Date").expect("malformed fallback uses shared Date contract");
    assert_eq!(date.len(), 29);
    assert_eq!(&date[3..5], ", ");
    assert!(date.ends_with(" GMT"));
    assert_eq!(header(head, "Content-Type"), Some("text/html"));
    assert_eq!(header(head, "Connection"), Some("close"));
    let length: usize = header(head, "Content-Length").unwrap().parse().unwrap();
    assert_eq!(length, body.len());
    assert_eq!(body, decoy::error_body(shared.server, 400, "Bad Request"));
    assert!(!body.contains("The plain HTTP request was sent to HTTPS port"));
    // Malformed encrypted input is a generic400, not the special cleartext-on-TLS page.
    let regular = decoy::http1_string(65535, false);
    let (regular_head, _) = regular.split_once("\r\n\r\n").unwrap();
    assert_eq!(header(head, "Server"), header(regular_head, "Server"));
}

#[tokio::test(start_paused = true)]
async fn malformed_legacy_blocked_write_keeps_original_admission_deadline() {
    let (mut client, mut server_io) = tokio::io::duplex(32);
    // Fits in the input half before polling; leave output unread to block write_all.
    client
        .write_all(&encode_stream_frame(b"malformed-not-sealed"))
        .await
        .unwrap();
    let auth = synthetic_keyring();
    let limits = ServerLimits::default();
    let policy = TargetPolicyConfig::default();
    let rate = RateLimiter::new(8, 60, false);
    let admission = AdmissionBudget::new(Duration::from_millis(100));
    let original_deadline = admission.deadline;
    let handling = handle_legacy_stream_session_with_admission(
        &mut server_io,
        &auth,
        "close",
        &limits,
        &policy,
        &rate,
        "192.0.2.10:49002".parse().unwrap(),
        admission,
    );
    tokio::pin!(handling);
    std::future::poll_fn(|cx| {
        assert!(handling.as_mut().poll(cx).is_pending());
        std::task::Poll::Ready(())
    })
    .await;
    tokio::time::advance(Duration::from_millis(99)).await;
    std::future::poll_fn(|cx| {
        assert!(handling.as_mut().poll(cx).is_pending());
        std::task::Poll::Ready(())
    })
    .await;
    tokio::time::advance(Duration::from_millis(2)).await;
    let error = handling
        .await
        .expect_err("fallback cannot renew the original clock");
    assert!(error.to_string().contains("fallback admission timed out"));
    assert_eq!(
        tokio::time::Instant::now() - original_deadline,
        Duration::from_millis(1)
    );
}

#[tokio::test]
async fn valid_current_and_legacy_requests_keep_encrypted_matched_key_responses() {
    for (selected, wrong) in [(CURRENT, LEGACY), (LEGACY, CURRENT)] {
        let (mut client, mut server_io) = tokio::io::duplex(8192);
        let mut server = OwnedTask(tokio::spawn(async move {
            handle_legacy_stream_session_with_admission(
                &mut server_io,
                &synthetic_keyring(),
                "close",
                &ServerLimits::default(),
                &TargetPolicyConfig::default(),
                &RateLimiter::new(8, 60, false),
                "192.0.2.10:49003".parse().unwrap(),
                AdmissionBudget::new(Duration::from_secs(2)),
            )
            .await
        }));
        let request = seal_tunnel_request(
            &TunnelRequest {
                host: "synthetic.example.invalid".into(),
                // Actual target policy rejects0 before lookup or connect.
                port: 0,
            },
            selected,
        )
        .unwrap();
        client
            .write_all(&encode_stream_frame(&request))
            .await
            .unwrap();
        let frame = tokio::time::timeout(
            Duration::from_secs(2),
            read_stream_frame(&mut client, MAX_TUNNEL_CONTROL_FRAME),
        )
        .await
        .unwrap()
        .unwrap();
        let response = open_tunnel_response(&frame, selected).unwrap();
        assert_eq!(response.status, TunnelStatus::BadTarget);
        assert!(response.message.contains("target port zero is not allowed"));
        assert!(open_tunnel_response(&frame, wrong).is_err());
        tokio::time::timeout(Duration::from_secs(2), &mut server.0)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }
}
