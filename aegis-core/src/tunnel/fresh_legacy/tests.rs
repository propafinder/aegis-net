use super::*;
use rand::{rngs::StdRng, SeedableRng};
use std::cell::Cell;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::Waker;
use std::time::Duration;

const SECRET: &[u8] = b"synthetic-audit9-key";

fn request() -> TunnelRequest {
    TunnelRequest {
        host: "target.invalid".into(),
        port: 0,
    }
}
fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(5)
}
fn ok() -> TunnelResponse {
    TunnelResponse {
        status: TunnelStatus::Ok,
        message: "ok".into(),
    }
}

#[test]
fn unchanged_v3_stateless_decoder_accepts_identical_authenticated_bytes_twice() {
    let request = request();
    let frame = crate::tunnel::seal_tunnel_request(&request, SECRET).unwrap();
    assert_eq!(
        crate::tunnel::open_tunnel_request(&frame, SECRET).unwrap(),
        request
    );
    assert_eq!(
        crate::tunnel::open_tunnel_request(&frame, SECRET).unwrap(),
        request
    );
}

#[tokio::test]
async fn raw_fresh_exchange_releases_exact_request_and_matched_migration_key_once() {
    let (mut client, mut server) = tokio::io::duplex(1024);
    let primary = 1u8;
    let migration = 2u8;
    let keys = [
        KeyCandidate {
            authority: &primary,
            secret: b"other-synthetic-key",
            expires: None,
        },
        KeyCandidate {
            authority: &migration,
            secret: SECRET,
            expires: None,
        },
    ];
    let calls = AtomicUsize::new(0);
    let limit = deadline();
    let expected = request();
    let client_future = exchange_raw(&mut client, &expected, SECRET, limit);
    let server_future = admit_raw(
        &mut server,
        &keys,
        limit,
        Duration::from_secs(5),
        |_| true,
        |got, authority| {
            assert_eq!(got, request());
            assert_eq!(*authority, migration);
            calls.fetch_add(1, Ordering::SeqCst);
            async { Ok((Some(()), ok())) }
        },
    );
    let (client_result, server_result) = tokio::join!(client_future, server_future);
    assert_eq!(client_result.unwrap(), ok());
    assert_eq!(server_result.unwrap(), Some(()));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn stored_proof_on_distinct_connection_challenge_never_calls_connector() {
    let authority = 7u8;
    let candidate = KeyCandidate {
        authority: &authority,
        secret: SECRET,
        expires: None,
    };
    let (open_frame, client) =
        ClientOpen::start_with_rng(&request(), SECRET, &mut StdRng::seed_from_u64(10)).unwrap();
    let (old_challenge, old_pending) = ServerPending::start_with_rng(
        &open_frame,
        &candidate,
        deadline(),
        &mut StdRng::seed_from_u64(20),
    )
    .unwrap();
    let (old_proof, old_client) = client
        .prove_with_rng(&old_challenge, &mut StdRng::seed_from_u64(30))
        .unwrap();
    let authenticated = old_pending.authenticate(&old_proof, |_| true).unwrap();
    let (_, old_final, _) = authenticated
        .connect(|_| true, |_, _| async { Ok((Some(()), ok())) })
        .await
        .unwrap();
    assert_eq!(old_client.finish(&old_final).unwrap(), ok());

    // New owner/entropy model, not a process-restart or deployed multi-relay test.
    let (mut client_io, mut server_io) = tokio::io::duplex(1024);
    let calls = AtomicUsize::new(0);
    let keys = [candidate];
    let limit = deadline();
    let mut entropy = StdRng::seed_from_u64(40);
    let server = admit_with_rng(
        &mut server_io,
        &keys,
        limit,
        Duration::from_secs(5),
        |_| true,
        |_, _| {
            calls.fetch_add(1, Ordering::SeqCst);
            async { Ok((Some(()), ok())) }
        },
        &mut entropy,
    );
    let replay = async {
        write(&mut client_io, &open_frame, limit).await.unwrap();
        let new_challenge = read(&mut client_io, limit).await.unwrap();
        assert_ne!(new_challenge, old_challenge);
        write(&mut client_io, &old_proof, limit).await.unwrap();
    };
    let (result, ()) = tokio::join!(server, replay);
    assert!(matches!(result, Err(AegisError::Auth)));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[test]
fn proof_is_bound_to_open_and_role_and_cannot_use_another_key() {
    let authority = 9u8;
    let key = KeyCandidate {
        authority: &authority,
        secret: SECRET,
        expires: None,
    };
    let (open_a, context) =
        ClientOpen::start_with_rng(&request(), SECRET, &mut StdRng::seed_from_u64(1)).unwrap();
    let (challenge, pending) =
        ServerPending::start_with_rng(&open_a, &key, deadline(), &mut StdRng::seed_from_u64(2))
            .unwrap();
    assert!(pending.authenticate(&challenge, |_| true).is_err());
    let (proof, _) = context
        .prove_with_rng(&challenge, &mut StdRng::seed_from_u64(3))
        .unwrap();
    let mut other = request();
    other.host = "other.invalid".into();
    let (open_b, _) =
        ClientOpen::start_with_rng(&other, SECRET, &mut StdRng::seed_from_u64(4)).unwrap();
    // Equal server RNG state gives the same server nonce, isolating binding.
    let (_, other_owner) =
        ServerPending::start_with_rng(&open_b, &key, deadline(), &mut StdRng::seed_from_u64(2))
            .unwrap();
    assert!(matches!(
        other_owner.authenticate(&proof, |_| true),
        Err(AegisError::Auth)
    ));
    assert!(open(Role::Proof, &proof, b"wrong-synthetic-key").is_err());
}

#[tokio::test]
async fn expired_matched_authority_before_proof_is_terminal_without_target() {
    let authority = 3u8;
    let keys = [KeyCandidate {
        authority: &authority,
        secret: SECRET,
        expires: None,
    }];
    let active = Cell::new(true);
    let calls = AtomicUsize::new(0);
    let (mut client, mut server) = tokio::io::duplex(1024);
    let limit = deadline();
    let server_future = admit_raw(
        &mut server,
        &keys,
        limit,
        Duration::from_secs(5),
        |_| active.get(),
        |_, _| {
            calls.fetch_add(1, Ordering::SeqCst);
            async { Ok((Some(()), ok())) }
        },
    );
    let client_future = async {
        let (frame, context) = ClientOpen::start(&request(), SECRET).unwrap();
        write(&mut client, &frame, limit).await.unwrap();
        let challenge = read(&mut client, limit).await.unwrap();
        let (proof, _) = context.prove(&challenge).unwrap();
        active.set(false);
        write(&mut client, &proof, limit).await.unwrap();
    };
    let (result, ()) = tokio::join!(server_future, client_future);
    assert!(matches!(result, Err(AegisError::Auth)));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn current_client_rejects_old_bound_final_and_accepts_bound_policy_error() {
    let authority = 1u8;
    let key = KeyCandidate {
        authority: &authority,
        secret: SECRET,
        expires: None,
    };
    let (frame, context) = ClientOpen::start(&request(), SECRET).unwrap();
    let (challenge, pending) = ServerPending::start(&frame, &key, deadline()).unwrap();
    let (proof, context) = context.prove(&challenge).unwrap();
    let response = TunnelResponse {
        status: TunnelStatus::BadTarget,
        message: "denied".into(),
    };
    let authenticated = pending.authenticate(&proof, |_| true).unwrap();
    let (_, old_final, _) = authenticated
        .connect(
            |_| true,
            |got, _| async move {
                assert_eq!(got.port, 0);
                Ok((None::<()>, response))
            },
        )
        .await
        .unwrap();
    assert_eq!(
        context.finish(&old_final).unwrap().status,
        TunnelStatus::BadTarget
    );
    let mut other = request();
    other.host = "other.invalid".into();
    let (other_frame, other_context) = ClientOpen::start(&other, SECRET).unwrap();
    let (other_challenge, _) = ServerPending::start(&other_frame, &key, deadline()).unwrap();
    let (_, other_context) = other_context.prove(&other_challenge).unwrap();
    assert!(matches!(
        other_context.finish(&old_final),
        Err(AegisError::Auth)
    ));
}

#[test]
fn frame_host_role_and_plaintext_lengths_fail_closed_and_v3_is_not_fresh_open() {
    let authority = 1u8;
    let key = KeyCandidate {
        authority: &authority,
        secret: SECRET,
        expires: None,
    };
    let (frame, _) = ClientOpen::start(&request(), SECRET).unwrap();
    let mut trailing = frame.clone();
    trailing.push(0);
    assert!(ServerPending::start(&trailing, &key, deadline()).is_err());
    let mut truncated = frame;
    truncated.truncate(ENVELOPE_OVERHEAD);
    assert!(ServerPending::start(&truncated, &key, deadline()).is_err());
    let malformed = seal(
        Role::Open,
        &[VERSION, Role::Open as u8, 0, 1],
        SECRET,
        &mut StdRng::seed_from_u64(1),
    )
    .unwrap();
    assert!(ServerPending::start(&malformed, &key, deadline()).is_err());
    let v3 = crate::tunnel::seal_tunnel_request(&request(), SECRET).unwrap();
    assert!(ServerPending::start(&v3, &key, deadline()).is_err());
    let huge = TunnelRequest {
        host: "x".repeat(MAX_TUNNEL_CONTROL_FRAME),
        port: 0,
    };
    assert!(ClientOpen::start(&huge, SECRET).is_err());
}

struct FailedEntropy;
impl CryptoRng for FailedEntropy {}
impl RngCore for FailedEntropy {
    fn next_u32(&mut self) -> u32 {
        panic!("unexpected infallible RNG path")
    }
    fn next_u64(&mut self) -> u64 {
        panic!("unexpected infallible RNG path")
    }
    fn fill_bytes(&mut self, _: &mut [u8]) {
        panic!("unexpected infallible RNG path")
    }
    fn try_fill_bytes(&mut self, _: &mut [u8]) -> std::result::Result<(), rand::Error> {
        Err(rand::Error::new(std::io::Error::other(
            "synthetic entropy failure",
        )))
    }
}

#[test]
fn fallible_rng_aborts_client_and_server_before_challenge_owner() {
    assert!(ClientOpen::start_with_rng(&request(), SECRET, &mut FailedEntropy).is_err());
    let authority = 1u8;
    let key = KeyCandidate {
        authority: &authority,
        secret: SECRET,
        expires: None,
    };
    let (frame, _) = ClientOpen::start(&request(), SECRET).unwrap();
    assert!(ServerPending::start_with_rng(&frame, &key, deadline(), &mut FailedEntropy).is_err());
}

#[test]
fn repeated_server_rng_state_is_explicit_replay_guarantee_boundary() {
    let authority = 1u8;
    let key = KeyCandidate {
        authority: &authority,
        secret: SECRET,
        expires: None,
    };
    let (frame, context) = ClientOpen::start(&request(), SECRET).unwrap();
    let (challenge, _) =
        ServerPending::start_with_rng(&frame, &key, deadline(), &mut StdRng::seed_from_u64(5))
            .unwrap();
    let (proof, _) = context.prove(&challenge).unwrap();
    let (_, repeated_owner) =
        ServerPending::start_with_rng(&frame, &key, deadline(), &mut StdRng::seed_from_u64(5))
            .unwrap();
    assert!(repeated_owner.authenticate(&proof, |_| true).is_ok());
}

#[tokio::test(start_paused = true)]
async fn deadline_guard_rejects_expired_first_poll_and_ready_after_controlled_clock_expiry() {
    let start = Instant::now();
    let limit = start + Duration::from_secs(1);
    let clock = Cell::new(limit);
    let polls = Cell::new(0usize);
    let mut cx = Context::from_waker(Waker::noop());
    let mut future = std::pin::pin!(poll_fn(|_| {
        polls.set(polls.get() + 1);
        clock.set(limit);
        Poll::Ready(Ok::<_, AegisError>(()))
    }));
    assert!(matches!(
        guarded_poll(future.as_mut(), &mut cx, limit, || clock.get()),
        Poll::Ready(Err(_))
    ));
    assert_eq!(polls.get(), 0);
    clock.set(start);
    assert!(matches!(
        guarded_poll(future.as_mut(), &mut cx, limit, || clock.get()),
        Poll::Ready(Err(_))
    ));
    assert_eq!(polls.get(), 1);
}

#[tokio::test(start_paused = true)]
async fn pending_proof_retains_original_budget_and_never_calls_connector() {
    let (mut client, mut server) = tokio::io::duplex(1024);
    let authority = 1u8;
    let keys = [KeyCandidate {
        authority: &authority,
        secret: SECRET,
        expires: None,
    }];
    let calls = AtomicUsize::new(0);
    let limit = Instant::now() + Duration::from_secs(1);
    let server_future = admit_raw(
        &mut server,
        &keys,
        limit,
        Duration::from_secs(5),
        |_| true,
        |_, _| {
            calls.fetch_add(1, Ordering::SeqCst);
            async { Ok((Some(()), ok())) }
        },
    );
    let silent_proof = async {
        let (frame, _) = ClientOpen::start(&request(), SECRET).unwrap();
        write(&mut client, &frame, limit).await.unwrap();
        read(&mut client, limit).await.unwrap();
        tokio::time::sleep(Duration::from_secs(2)).await;
    };
    let (result, ()) = tokio::join!(server_future, silent_proof);
    assert!(matches!(result, Err(AegisError::RelayCodec(ref message))
        if message == "fresh legacy admission deadline expired"));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[tokio::test(start_paused = true)]
async fn matched_key_expiry_cancels_pending_target_before_later_admission_cutoff() {
    let authority = 1u8;
    let expiry = Instant::now() + Duration::from_secs(1);
    let candidate = KeyCandidate {
        authority: &authority,
        secret: SECRET,
        expires: Some(expiry),
    };
    let (frame, context) = ClientOpen::start(&request(), SECRET).unwrap();
    let (challenge, pending) =
        ServerPending::start(&frame, &candidate, Instant::now() + Duration::from_secs(5)).unwrap();
    let (proof, _) = context.prove(&challenge).unwrap();
    let authenticated = pending.authenticate(&proof, |_| true).unwrap();
    let contacts = AtomicUsize::new(0);
    let result = authenticated
        .connect(
            |_| true,
            |_, _| async {
                tokio::time::sleep(Duration::from_secs(2)).await;
                contacts.fetch_add(1, Ordering::SeqCst);
                Ok((Some(()), ok()))
            },
        )
        .await;
    assert!(result.is_err());
    assert_eq!(Instant::now(), expiry);
    assert_eq!(contacts.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn explicit_client_rejects_old_v3_ok_without_proof_or_application_payload() {
    let (mut client, mut server) = tokio::io::duplex(4096);
    let limit = deadline();
    let request = request();
    let attempted = exchange_raw(&mut client, &request, SECRET, limit);
    let old_peer = async move {
        let fresh_open = read(&mut server, limit).await.unwrap();
        assert!(crate::tunnel::open_tunnel_request(&fresh_open, SECRET).is_err());
        let v3_ok = crate::tunnel::seal_tunnel_response(&ok(), SECRET).unwrap();
        write(&mut server, &v3_ok, limit).await.unwrap();
        server
    };
    let (result, mut server) = tokio::join!(attempted, old_peer);
    assert!(result.is_err());
    drop(client);
    let mut extra = Vec::new();
    use tokio::io::AsyncReadExt;
    tokio::time::timeout_at(limit, server.read_to_end(&mut extra))
        .await
        .unwrap()
        .unwrap();
    assert!(
        extra.is_empty(),
        "no proof or application bytes follow an old v3 response"
    );
}

#[tokio::test(start_paused = true)]
async fn blocked_control_write_uses_existing_write_budget_without_renewing_setup() {
    let (mut sender, _unread_peer) = tokio::io::duplex(1);
    let start = Instant::now();
    let original = start + Duration::from_secs(5);
    let result = write_control(&mut sender, &[0; 16], original, Duration::from_secs(1)).await;
    assert!(result.is_err());
    assert_eq!(Instant::now(), start + Duration::from_secs(1));
    let (mut sender, _unread_peer) = tokio::io::duplex(1);
    let original = Instant::now() + Duration::from_secs(1);
    let result = write_control(&mut sender, &[0; 16], original, Duration::from_secs(5)).await;
    assert!(result.is_err());
    assert_eq!(
        Instant::now(),
        original,
        "write policy cannot extend the original setup cutoff"
    );
}
