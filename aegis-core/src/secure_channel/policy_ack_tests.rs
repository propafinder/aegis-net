use super::*;
use std::time::Duration;

fn ack() -> RuntimePolicyAck {
    RuntimePolicyAck {
        version: 1,
        nonce: "01".repeat(32),
        generation: 5,
        snapshot_sha256: "02".repeat(32),
        certificate_sha256: "03".repeat(32),
        policy_not_after_unix_secs: 200,
        certificate_not_after_unix_secs: 300,
        effective_valid_for_ms: 2999,
    }
}

#[test]
fn verification_binds_request_device_generation_digest_and_expiry() {
    let good = ack();
    let verify = |ack: &RuntimePolicyAck| {
        ack.verify(
            &good.nonce,
            &good.certificate_sha256,
            Some((5, &good.snapshot_sha256)),
            100,
            Duration::ZERO,
        )
    };
    verify(&good).unwrap();
    for field in 0..8 {
        let mut bad = good.clone();
        match field {
            0 => bad.nonce = "04".repeat(32),
            1 => bad.certificate_sha256 = "04".repeat(32),
            2 => bad.generation = 4,
            3 => bad.snapshot_sha256 = "04".repeat(32),
            4 => bad.policy_not_after_unix_secs = 100,
            5 => bad.certificate_not_after_unix_secs = 100,
            6 => bad.effective_valid_for_ms = 0,
            _ => bad.effective_valid_for_ms = 3001,
        }
        assert!(verify(&bad).is_err(), "field {field}");
    }
    let mut newer = good.clone();
    newer.generation += 1;
    newer.snapshot_sha256 = "04".repeat(32);
    verify(&newer).unwrap();
    good.verify(
        &good.nonce,
        &good.certificate_sha256,
        None,
        100,
        Duration::ZERO,
    )
    .unwrap();
    assert!(good
        .verify(
            &good.nonce,
            &good.certificate_sha256,
            Some((0, "bad")),
            100,
            Duration::ZERO
        )
        .is_err());
}

#[test]
fn delayed_authenticated_ack_expires_on_client_monotonic_roundtrip() {
    let good = ack();
    for elapsed in [2999, 3000, 10_000] {
        assert!(good
            .verify(
                &good.nonce,
                &good.certificate_sha256,
                None,
                100,
                Duration::from_millis(elapsed)
            )
            .is_err());
    }
    assert_eq!(
        good.verify(
            &good.nonce,
            &good.certificate_sha256,
            None,
            100,
            Duration::from_millis(2900)
        )
        .unwrap(),
        Duration::from_millis(99)
    );
}

#[tokio::test]
async fn control_roundtrip_and_legacy_open_bytes_are_compatible() {
    let request = PolicyAckRequest::new();
    let next = PolicyAckRequest::new();
    assert_ne!(request.nonce, next.nonce);
    let mut bytes = Vec::new();
    write_request(&mut bytes, &request).await.unwrap();
    let ChannelRequest::PolicyAck(parsed) = read_request(&mut bytes.as_slice()).await.unwrap()
    else {
        panic!("control became target open")
    };
    assert_eq!(parsed.nonce, request.nonce);
    let mut bytes = Vec::new();
    super::super::write_open(
        &mut bytes,
        &OpenRequest {
            version: 1,
            host: "example.test".into(),
            port: 443,
            transport: super::super::Transport::Tcp,
        },
    )
    .await
    .unwrap();
    let ChannelRequest::Open(parsed) = read_request(&mut bytes.as_slice()).await.unwrap() else {
        panic!("old open became control")
    };
    assert_eq!(parsed.host, "example.test");
    assert_eq!(parsed.port, 443);
    let mut bytes = Vec::new();
    write_ack(&mut bytes, &ack()).await.unwrap();
    assert_eq!(read_ack(&mut bytes.as_slice()).await.unwrap().generation, 5);
}

#[tokio::test]
async fn malformed_ambiguous_or_oversized_control_frames_are_rejected() {
    for value in [
        serde_json::json!({"version":1,"operation":"policy_ack","nonce":"01".repeat(32),"host":"example.test","port":443}),
        serde_json::json!({"version":1,"operation":"dial","nonce":"01".repeat(32)}),
        serde_json::json!({"version":1,"operation":"policy_ack","nonce":"secret"}),
        serde_json::json!({"version":2,"operation":"policy_ack","nonce":"01".repeat(32)}),
    ] {
        let mut bytes = Vec::new();
        write(&mut bytes, &value).await.unwrap();
        assert!(read_request(&mut bytes.as_slice()).await.is_err());
    }
    for length in [0, 1025, 65535u16] {
        assert!(read_request(&mut length.to_be_bytes().as_slice())
            .await
            .is_err());
        assert!(read_ack(&mut length.to_be_bytes().as_slice())
            .await
            .is_err());
    }
    let mut extra = serde_json::to_value(ack()).unwrap();
    extra["unknown"] = true.into();
    let mut bytes = Vec::new();
    write(&mut bytes, &extra).await.unwrap();
    assert!(read_ack(&mut bytes.as_slice()).await.is_err());
}
