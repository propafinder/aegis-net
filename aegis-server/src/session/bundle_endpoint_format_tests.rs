use super::tests::transaction_fixture;
use super::*;

#[tokio::test(start_paused = true)]
async fn actual_malformed_token_refuses_before_waiting_for_store_mutex() {
    let (_dir, ctx, _issued_token, _bundle) = transaction_fixture();
    let _held = ctx.store.clone().lock_owned().await;
    for malformed in [
        "short".to_owned(),
        "A".repeat(64),
        "g".repeat(64),
        "0".repeat(63),
        "0".repeat(65),
        "%30".repeat(64),
        "é".repeat(32),
        format!("{} ", "0".repeat(63)),
    ] {
        let query = format!("token={malformed}");
        let completed = tokio::time::timeout(
            Duration::from_millis(50),
            redeem_bundle_bytes_with_reader(
                &ctx,
                "/bundle",
                Some(&query),
                "127.0.0.1:1".parse().unwrap(),
                |_| {
                    std::future::ready(Err::<Vec<u8>, _>(std::io::Error::other(
                        "reader must not run",
                    )))
                },
            ),
        )
        .await;
        assert!(matches!(
            completed,
            Ok(Err(BundleHandlerError::MissingToken))
        ));
    }
}

#[tokio::test]
async fn actual_malformed_token_refuses_before_rereading_corrupted_owned_store() {
    let (_dir, ctx, _issued_token, _bundle) = transaction_fixture();
    std::fs::write(&ctx.config.token_store_path, b"invalid store fixture").unwrap();
    let result = redeem_bundle_bytes(
        &ctx,
        "/bundle",
        Some("token=short"),
        "127.0.0.1:1".parse().unwrap(),
    )
    .await;
    assert!(matches!(result, Err(BundleHandlerError::MissingToken)));
}

#[tokio::test]
async fn actual_canonical_issued_token_keeps_fresh_reload_failure_closed() {
    let (_dir, ctx, issued_token, _bundle) = transaction_fixture();
    std::fs::write(&ctx.config.token_store_path, b"invalid store fixture").unwrap();
    let query = format!("token={issued_token}");
    let result = redeem_bundle_bytes(
        &ctx,
        "/bundle",
        Some(&query),
        "127.0.0.1:1".parse().unwrap(),
    )
    .await;
    assert!(matches!(
        result,
        Err(BundleHandlerError::Token(BundleTokenError::PersistFailed(
            _
        )))
    ));
}

#[tokio::test(start_paused = true)]
async fn actual_canonical_miss_still_waits_for_store_mutex() {
    let (_dir, ctx, _issued_token, _bundle) = transaction_fixture();
    let _held = ctx.store.clone().lock_owned().await;
    let query = format!("token={}", "0".repeat(64));
    let result = tokio::time::timeout(
        Duration::from_millis(50),
        redeem_bundle_bytes(
            &ctx,
            "/bundle",
            Some(&query),
            "127.0.0.1:1".parse().unwrap(),
        ),
    )
    .await;
    assert!(
        result.is_err(),
        "canonical misses retain the locked store path"
    );
}
