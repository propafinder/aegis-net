//! Explicit feature admission prevents retrying a fresh raw session via v3.
use aegis_core::TunnelTransportFamily;

pub(super) fn require_raw_tcp_order(
    inner_tls: bool,
    order: &[TunnelTransportFamily],
) -> anyhow::Result<()> {
    // Device mTLS owns its separate authenticated carrier and is unchanged.
    if inner_tls {
        return Ok(());
    }
    anyhow::ensure!(
        !order.is_empty() && order.iter().all(|family| *family == TunnelTransportFamily::LegacyTls),
        "legacy-challenge-v1 requires a raw legacy_tls-only TCP transport order; downgrade is refused"
    );
    Ok(())
}

// Compatibility with the enclosing raw opening owner: only the exact private
// core deadline marker, observed after its original cutoff, becomes Elapsed.
// This effect-free pending future uses that already-expired cutoff; it does not
// create another timeout window or change ordinary I/O/authentication errors.
pub(super) async fn opening_error(
    error: aegis_core::AegisError,
    original_cutoff: tokio::time::Instant,
) -> anyhow::Error {
    if matches!(&error, aegis_core::AegisError::RelayCodec(message)
        if message == "fresh legacy admission deadline expired")
        && tokio::time::Instant::now() >= original_cutoff
    {
        return tokio::time::timeout_at(original_cutoff, std::future::pending::<()>())
            .await
            .expect_err("effect-free pending future at expired original cutoff")
            .into();
    }
    error.into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_raw_feature_admits_only_raw_retries() {
        assert!(require_raw_tcp_order(false, &[TunnelTransportFamily::LegacyTls]).is_ok());
        assert!(require_raw_tcp_order(
            false,
            &[
                TunnelTransportFamily::LegacyTls,
                TunnelTransportFamily::LegacyTls,
            ]
        )
        .is_ok());
    }

    #[test]
    fn explicit_raw_feature_refuses_empty_and_fallback_family_before_dial() {
        assert!(require_raw_tcp_order(false, &[]).is_err());
        assert!(require_raw_tcp_order(
            false,
            &[
                TunnelTransportFamily::LegacyTls,
                TunnelTransportFamily::HttpsWs,
            ]
        )
        .is_err());
        assert!(require_raw_tcp_order(false, &[TunnelTransportFamily::MasqueDerived]).is_err());
    }

    #[test]
    fn existing_inner_mtls_transport_admission_is_unchanged() {
        assert!(require_raw_tcp_order(true, &[TunnelTransportFamily::HttpsWs]).is_ok());
    }

    #[tokio::test(start_paused = true)]
    async fn opening_deadline_adapter_preserves_original_cutoff_and_other_errors() {
        use aegis_core::AegisError;
        use tokio::time::{Duration, Instant};
        let cutoff = Instant::now() + Duration::from_millis(100);
        let marker = || AegisError::RelayCodec("fresh legacy admission deadline expired".into());
        let premature = opening_error(marker(), cutoff).await;
        assert!(matches!(premature.downcast_ref::<AegisError>(),
            Some(AegisError::RelayCodec(message)) if message == "fresh legacy admission deadline expired"));
        assert!(premature
            .downcast_ref::<tokio::time::error::Elapsed>()
            .is_none());
        tokio::time::advance(Duration::from_millis(100)).await;
        let before = Instant::now();
        let expired = opening_error(marker(), cutoff).await;
        assert!(expired
            .downcast_ref::<tokio::time::error::Elapsed>()
            .is_some());
        assert_eq!(Instant::now(), before, "no renewed opening budget");
        assert_eq!(before, cutoff);
        let io = opening_error(
            AegisError::Io(std::io::Error::new(
                std::io::ErrorKind::ConnectionReset,
                "synthetic real I/O failure",
            )),
            cutoff,
        )
        .await;
        assert!(
            matches!(io.downcast_ref::<AegisError>(), Some(AegisError::Io(error))
            if error.kind() == std::io::ErrorKind::ConnectionReset)
        );
        let auth = opening_error(AegisError::Auth, cutoff).await;
        assert!(matches!(
            auth.downcast_ref::<AegisError>(),
            Some(AegisError::Auth)
        ));
        let codec = opening_error(
            AegisError::RelayCodec("different malformed frame".into()),
            cutoff,
        )
        .await;
        assert!(matches!(codec.downcast_ref::<AegisError>(),
            Some(AegisError::RelayCodec(message)) if message == "different malformed frame"));
    }
}
