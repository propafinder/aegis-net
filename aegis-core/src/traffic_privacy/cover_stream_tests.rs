use super::*;
use rand::{rngs::StdRng, SeedableRng};
use tokio::time::timeout;

fn settings() -> CoverStreamSettings {
    CoverStreamSettings {
        tokens: vec![b"a".to_vec(), b"b".to_vec(), b"c".to_vec()],
        weights: vec![4, 2, 1],
        conditional_model: None,
        capacity: 4,
        horizon: 256,
        max_records: 32,
        buffer_bytes: 32,
        max_wire_bytes: 32 * 256,
        io_timeout_ms: 2000,
        session_timeout_ms: 10000,
    }
}
fn material(seed: u8, direction: u8) -> CoverStreamMaterial {
    CoverStreamMaterial::new(Zeroizing::new([seed; 32]), direction).unwrap()
}
fn pair() -> (CoverStream, CoverStream) {
    let (a, b) = tokio::io::duplex(1024);
    let original = Instant::now() + Duration::from_secs(10);
    (
        attach_authenticated(a, settings(), material(7, 0), material(9, 1), original).unwrap(),
        attach_authenticated(b, settings(), material(9, 1), material(7, 0), original).unwrap(),
    )
}
async fn encoded(
    s: &CoverStreamSettings,
    seed: u8,
    direction: u8,
    ordinal: u64,
    payload: &[u8],
) -> Vec<u8> {
    let model = s.model().unwrap();
    let profile = s.descriptor().unwrap();
    let record = material(seed, direction)
        .record(&model, &profile, ordinal)
        .unwrap();
    let mut bytes = Vec::new();
    record
        .send(payload, &mut StdRng::seed_from_u64(42), &mut bytes)
        .await
        .unwrap();
    assert_eq!(bytes.len(), s.wire_bytes().unwrap());
    bytes
}

#[test]
fn closed_profile_and_bounds_bind_all_settings() {
    let s = settings();
    s.validate().unwrap();
    let json = serde_json::to_vec(&s).unwrap();
    assert_eq!(
        serde_json::from_slice::<CoverStreamSettings>(&json).unwrap(),
        s
    );
    let mut other = s.clone();
    other.weights[0] += 1;
    assert_ne!(s.descriptor().unwrap(), other.descriptor().unwrap());
    let mut other = s.clone();
    other.max_records -= 1;
    assert_ne!(s.descriptor().unwrap(), other.descriptor().unwrap());
    let mut other = s.clone();
    other.capacity = 1;
    assert!(other.validate().is_err());
    let mut other = s.clone();
    other.max_records = u64::MAX;
    assert!(other.validate().is_err());
    let mut other = s.clone();
    other.max_wire_bytes -= 1;
    assert!(other.validate().is_err());
    let mut other = s.clone();
    other.tokens[1] = other.tokens[0].clone();
    assert!(other.validate().is_err());
    let mut other = s.clone();
    other.weights = vec![0, 0, 0];
    assert!(other.validate().is_err());
    let mut other = s.clone();
    other.capacity = 256;
    other.horizon = 4096;
    assert!(other.validate().is_err());
    let mut value = serde_json::to_value(&s).unwrap();
    value["unexpected"] = true.into();
    assert!(serde_json::from_value::<CoverStreamSettings>(value).is_err());
    assert!(CoverStreamMaterial::new(Zeroizing::new([0; 32]), 2).is_err());
}

#[tokio::test]
async fn arbitrary_cover_actual_fifo_bidirectional_half_close() {
    let (mut a, mut b) = pair();
    let sender = tokio::spawn(async move {
        a.write_all(b"firstabcdef").await.unwrap();
        a.shutdown().await.unwrap();
        let mut response = Vec::new();
        a.read_to_end(&mut response).await.unwrap();
        (response, a.finish().await.unwrap())
    });
    let mut input = Vec::new();
    b.read_to_end(&mut input).await.unwrap();
    assert_eq!(input, b"firstabcdef");
    b.write_all(b"reply").await.unwrap();
    b.shutdown().await.unwrap();
    let b_stats = b.finish().await.unwrap();
    let (response, a_stats) = sender.await.unwrap();
    assert_eq!(response, b"reply");
    assert_eq!(a_stats.sent.data_bytes, 11);
    assert_eq!(a_stats.sent.wire_bytes, b_stats.received.wire_bytes);
    assert_eq!(a_stats.sent.wire_bytes, a_stats.sent.frames * 256);
    assert_eq!(b_stats.sent.data_bytes, 5);
}

#[tokio::test]
async fn complete_record_verification_before_any_application_output() {
    let s = settings();
    let bytes = encoded(&s, 9, 1, 0, b"\x01abc").await;
    let (wire, mut peer) = tokio::io::duplex(1024);
    let mut app = attach_authenticated(
        wire,
        s.clone(),
        material(7, 0),
        material(9, 1),
        Instant::now() + Duration::from_secs(5),
    )
    .unwrap();
    peer.write_all(&bytes[..bytes.len() - 1]).await.unwrap();
    let mut out = [0u8; 3];
    assert!(timeout(Duration::from_millis(30), app.read_exact(&mut out))
        .await
        .is_err());
    peer.write_all(&bytes[bytes.len() - 1..]).await.unwrap();
    app.read_exact(&mut out).await.unwrap();
    assert_eq!(&out, b"abc");
    let end = encoded(&s, 9, 1, 1, b"\x00").await;
    peer.write_all(&end).await.unwrap();
    let mut rest = Vec::new();
    app.read_to_end(&mut rest).await.unwrap();
    assert!(rest.is_empty());
}

#[tokio::test]
async fn replayed_record_fails_next_ordinal_with_sticky_error() {
    let s = settings();
    let bytes = encoded(&s, 9, 1, 0, b"\x01abc").await;
    let (wire, mut peer) = tokio::io::duplex(1024);
    let mut app = attach_authenticated(
        wire,
        s,
        material(7, 0),
        material(9, 1),
        Instant::now() + Duration::from_secs(5),
    )
    .unwrap();
    peer.write_all(&bytes).await.unwrap();
    let mut out = [0u8; 3];
    app.read_exact(&mut out).await.unwrap();
    peer.write_all(&bytes).await.unwrap();
    let mut one = [0u8; 1];
    let first = app.read(&mut one).await.unwrap_err();
    assert_eq!(first.kind(), io::ErrorKind::InvalidData);
    assert_eq!(app.read(&mut one).await.unwrap_err().kind(), first.kind());
}

#[tokio::test]
async fn malformed_tokens_wrong_profile_and_wrong_frame_type_refuse_without_output() {
    for variant in 0..3 {
        let s = settings();
        let mut source = s.clone();
        if variant == 1 {
            source.session_timeout_ms -= 1;
        }
        let payload = if variant == 2 {
            b"\x00x".as_slice()
        } else {
            b"\x01abc".as_slice()
        };
        let mut bytes = encoded(&source, 9, 1, 0, payload).await;
        if variant == 0 {
            bytes[0] = b'z';
        }
        let (wire, mut peer) = tokio::io::duplex(1024);
        let mut app = attach_authenticated(
            wire,
            s,
            material(7, 0),
            material(9, 1),
            Instant::now() + Duration::from_secs(5),
        )
        .unwrap();
        peer.write_all(&bytes).await.unwrap();
        let mut out = [0u8; 1];
        assert_eq!(
            app.read(&mut out).await.unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }
}

#[tokio::test]
async fn record_allowance_exhaustion_does_not_manufacture_clean_eof() {
    let mut s = settings();
    s.max_records = 2;
    s.max_wire_bytes = 512;
    let (wire, mut peer) = tokio::io::duplex(1024);
    let mut app = attach_authenticated(
        wire,
        s.clone(),
        material(7, 0),
        material(9, 1),
        Instant::now() + Duration::from_secs(5),
    )
    .unwrap();
    peer.write_all(&encoded(&s, 9, 1, 0, b"\x01a").await)
        .await
        .unwrap();
    let mut first = [0u8; 1];
    app.read_exact(&mut first).await.unwrap();
    assert_eq!(first[0], b'a');
    peer.write_all(&encoded(&s, 9, 1, 1, b"\x01a").await)
        .await
        .unwrap();
    // The last verified byte may already be buffered when sticky exhaustion wins
    // the app poll. Either prefix is valid; NO successful EOF/finish is allowed.
    let mut out = [0u8; 1];
    match app.read(&mut out).await {
        Ok(1) => {
            assert_eq!(out[0], b'a');
            assert_eq!(
                app.read(&mut out).await.unwrap_err().kind(),
                io::ErrorKind::InvalidData
            );
        }
        Err(e) => assert_eq!(e.kind(), io::ErrorKind::InvalidData),
        other => panic!("exhaustion manufactured terminal success: {other:?}"),
    }
    assert_eq!(
        app.finish().await.unwrap_err().kind(),
        io::ErrorKind::InvalidData
    );
}

#[tokio::test]
async fn original_deadline_partial_eof_and_stalled_backpressure_are_bounded() {
    let (wire, _peer) = tokio::io::duplex(1);
    assert!(attach_authenticated(
        wire,
        settings(),
        material(7, 0),
        material(9, 1),
        Instant::now()
    )
    .is_err());
    let (wire, mut peer) = tokio::io::duplex(1);
    let mut s = settings();
    s.io_timeout_ms = 50;
    let mut app = attach_authenticated(
        wire,
        s,
        material(7, 0),
        material(9, 1),
        Instant::now() + Duration::from_millis(150),
    )
    .unwrap();
    app.write_all(b"abc").await.unwrap();
    assert_eq!(
        timeout(Duration::from_secs(1), app.shutdown())
            .await
            .unwrap()
            .unwrap_err()
            .kind(),
        io::ErrorKind::TimedOut
    );
    let mut wire_prefix = Vec::new();
    peer.read_to_end(&mut wire_prefix).await.unwrap();
    assert!(wire_prefix.len() <= 1);
    let (wire, mut peer) = tokio::io::duplex(1024);
    let mut app = attach_authenticated(
        wire,
        settings(),
        material(7, 0),
        material(9, 1),
        Instant::now() + Duration::from_secs(2),
    )
    .unwrap();
    peer.write_all(b"a").await.unwrap();
    peer.shutdown().await.unwrap();
    let mut out = [0u8; 1];
    assert_eq!(
        app.read(&mut out).await.unwrap_err().kind(),
        io::ErrorKind::UnexpectedEof
    );
}

#[tokio::test]
async fn owner_drop_closes_owned_transport_and_preserves_unrelated_child_task() {
    let (wire, mut peer) = tokio::io::duplex(1024);
    let app = attach_authenticated(
        wire,
        settings(),
        material(7, 0),
        material(9, 1),
        Instant::now() + Duration::from_secs(2),
    )
    .unwrap();
    let (tx, mut rx) = tokio::sync::mpsc::channel(1);
    let spectator = tokio::spawn(async move { rx.recv().await });
    drop(app);
    let mut byte = [0u8; 1];
    assert_eq!(
        timeout(Duration::from_secs(1), peer.read(&mut byte))
            .await
            .unwrap()
            .unwrap(),
        0
    );
    tx.send(42).await.unwrap();
    assert_eq!(spectator.await.unwrap(), Some(42));
}

#[tokio::test]
async fn per_ordinal_and_direction_material_authenticates_exact_profile() {
    let s = settings();
    let model = s.model().unwrap();
    let profile = s.descriptor().unwrap();
    let a = material(7, 0);
    let b = material(7, 1);
    // Constructors reject wrong direction and same-direction duplex installation.
    assert!(a.record(&model, &profile, 0).is_ok());
    assert!(b.record(&model, &profile, u64::MAX).is_ok());
    let bytes = encoded(&s, 7, 0, 0, b"\x01abc").await;
    let mut wrong_direction = bytes.as_slice();
    assert_eq!(
        b.record(&model, &profile, 0)
            .unwrap()
            .receive(&mut wrong_direction)
            .await
            .unwrap_err()
            .kind(),
        io::ErrorKind::InvalidData
    );
    let mut right_direction = bytes.as_slice();
    assert_eq!(
        a.record(&model, &profile, 0)
            .unwrap()
            .receive(&mut right_direction)
            .await
            .unwrap()
            .as_slice(),
        b"\x01abc"
    );
    let (wire, _) = tokio::io::duplex(1);
    assert!(attach_authenticated(
        wire,
        s,
        material(7, 0),
        material(9, 0),
        Instant::now() + Duration::from_secs(1)
    )
    .is_err());
}

#[tokio::test]
async fn complete_byte_alphabet_roundtrips_in_real_fixed_cover_records() {
    let mut s = settings();
    s.capacity = 17;
    s.horizon = 512;
    s.max_wire_bytes = 32 * 512;
    s.io_timeout_ms = 5000;
    s.session_timeout_ms = 30000;
    s.buffer_bytes = 256;
    let original = Instant::now() + Duration::from_secs(30);
    let (left, right) = tokio::io::duplex(1024);
    let mut a =
        attach_authenticated(left, s.clone(), material(7, 0), material(9, 1), original).unwrap();
    let mut b = attach_authenticated(right, s, material(9, 1), material(7, 0), original).unwrap();
    let sender = tokio::spawn(async move {
        a.write_all(&(0u8..=255).collect::<Vec<_>>()).await.unwrap();
        a.shutdown().await.unwrap();
        let mut response = Vec::new();
        a.read_to_end(&mut response).await.unwrap();
        a.finish().await.unwrap()
    });
    let mut received = Vec::new();
    b.read_to_end(&mut received).await.unwrap();
    assert_eq!(received, (0u8..=255).collect::<Vec<_>>());
    b.shutdown().await.unwrap();
    let stats = b.finish().await.unwrap();
    let other = sender.await.unwrap();
    assert_eq!(stats.received.data_bytes, 256);
    assert_eq!(stats.received.frames, 17);
    assert_eq!(stats.received.wire_bytes, other.sent.wire_bytes);
}

#[tokio::test]
async fn sender_exhaustion_before_end_remains_failure() {
    let mut s = settings();
    s.max_records = 2;
    s.max_wire_bytes = 512;
    let (wire, mut peer) = tokio::io::duplex(1024);
    let mut app = attach_authenticated(
        wire,
        s.clone(),
        material(7, 0),
        material(9, 1),
        Instant::now() + Duration::from_secs(5),
    )
    .unwrap();
    app.write_all(b"abcdef").await.unwrap();
    assert_eq!(
        app.shutdown().await.unwrap_err().kind(),
        io::ErrorKind::InvalidData
    );
    let mut bytes = Vec::new();
    peer.read_to_end(&mut bytes).await.unwrap();
    assert_eq!(bytes.len(), 512);
    let model = s.model().unwrap();
    let profile = s.descriptor().unwrap();
    for (ordinal, frame) in bytes.chunks_exact(256).enumerate() {
        let mut frame = frame;
        let plain = material(7, 0)
            .record(&model, &profile, ordinal as u64)
            .unwrap()
            .receive(&mut frame)
            .await
            .unwrap();
        assert_eq!(plain[0], 1);
        assert_eq!(plain.len(), 4); // both DATA, never disguised END
    }
    assert_eq!(
        app.finish().await.unwrap_err().kind(),
        io::ErrorKind::InvalidData
    );
}

fn conditional_settings() -> CoverStreamSettings {
    let mut s = settings();
    s.weights = vec![2, 1, 1];
    s.conditional_model = Some(
        crate::traffic_privacy::general_coupling::ConditionalCoverSettings {
            initial_state: 0,
            state_weights: vec![s.weights.clone(), vec![1, 2, 1]],
            next_states: vec![vec![0, 1, 0], vec![0, 1, 0]],
        },
    );
    s
}

#[test]
fn conditional_profile_binds_entire_table_state_and_clock_and_refuses_null() {
    let s = conditional_settings();
    s.validate().unwrap();
    let json = serde_json::to_value(&s).unwrap();
    assert_eq!(
        serde_json::from_value::<CoverStreamSettings>(json.clone()).unwrap(),
        s
    );
    for variant in 0..4 {
        let mut other = s.clone();
        let model = other.conditional_model.as_mut().unwrap();
        match variant {
            0 => model.state_weights[1] = vec![2, 1, 1],
            1 => model.next_states[1][0] = 1,
            2 => {
                model.initial_state = 1;
                other.weights = model.state_weights[1].clone();
            }
            3 => other.io_timeout_ms += 1,
            _ => unreachable!(),
        }
        assert_ne!(
            s.model().unwrap().descriptor_sha256(),
            other.model().unwrap().descriptor_sha256()
        );
        assert_ne!(s.descriptor().unwrap(), other.descriptor().unwrap());
    }
    let mut inconsistent = s.clone();
    inconsistent.weights[0] += 1;
    assert!(inconsistent.validate().is_err());
    let mut null = json.clone();
    null["conditional_model"] = serde_json::Value::Null;
    assert!(serde_json::from_value::<CoverStreamSettings>(null).is_err());
    let mut unknown = json;
    unknown["conditional_model"]["unknown"] = true.into();
    assert!(serde_json::from_value::<CoverStreamSettings>(unknown).is_err());
    let memoryless = serde_json::to_value(settings()).unwrap();
    assert!(memoryless.get("conditional_model").is_none());
    assert!(serde_json::from_value::<CoverStreamSettings>(memoryless)
        .unwrap()
        .conditional_model
        .is_none());
}

#[tokio::test]
async fn conditional_cover_actual_fifo_bidirectional_half_close() {
    let (left, right) = tokio::io::duplex(1024);
    let s = conditional_settings();
    let original = Instant::now() + Duration::from_secs(10);
    let mut a =
        attach_authenticated(left, s.clone(), material(7, 0), material(9, 1), original).unwrap();
    let mut b = attach_authenticated(right, s, material(9, 1), material(7, 0), original).unwrap();
    let sender = tokio::spawn(async move {
        a.write_all(b"firstabcdef").await.unwrap();
        a.shutdown().await.unwrap();
        let mut response = Vec::new();
        a.read_to_end(&mut response).await.unwrap();
        (response, a.finish().await.unwrap())
    });
    let mut input = Vec::new();
    b.read_to_end(&mut input).await.unwrap();
    assert_eq!(input, b"firstabcdef");
    b.write_all(b"reply").await.unwrap();
    b.shutdown().await.unwrap();
    let b_stats = b.finish().await.unwrap();
    let (response, a_stats) = sender.await.unwrap();
    assert_eq!(response, b"reply");
    assert_eq!(a_stats.sent.data_bytes, 11);
    assert_eq!(a_stats.sent.wire_bytes, b_stats.received.wire_bytes);
    assert_eq!(a_stats.sent.wire_bytes, a_stats.sent.frames * 256);
    assert_eq!(b_stats.sent.data_bytes, 5);
}

#[tokio::test]
async fn conditional_profile_transition_disagreement_releases_no_plaintext() {
    let s = conditional_settings();
    let mut other = s.clone();
    // Identical conditional PMFs in both peers, but a different complete
    // transition descriptor still cannot authenticate the same cover record.
    other.conditional_model.as_mut().unwrap().next_states[1][0] = 1;
    let bytes = encoded(&other, 9, 1, 0, b"\x01abc").await;
    let (wire, mut peer) = tokio::io::duplex(1024);
    let mut app = attach_authenticated(
        wire,
        s,
        material(7, 0),
        material(9, 1),
        Instant::now() + Duration::from_secs(5),
    )
    .unwrap();
    peer.write_all(&bytes).await.unwrap();
    let mut output = [0u8; 1];
    assert_eq!(
        app.read(&mut output).await.unwrap_err().kind(),
        io::ErrorKind::InvalidData
    );
    assert_eq!(output, [0]);
}
