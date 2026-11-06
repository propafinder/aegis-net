//! Exclusive CDN-fronted, device-enrolled origin.
//!
//! Only HTTP/2 requests carrying the CDN-injected origin key, exact authority,
//! POST, one `application/grpc` content type and a fixed enrolled path reach
//! inner device TLS or the enrollment forwarder. Everything else, including a
//! direct probe of the origin address, RFC 8441 Extended CONNECT and HTTP/1.1,
//! receives the ordinary public decoy. The origin key is a CDN-path check,
//! never a device credential: inner mTLS, the device registry, target policy
//! and enrollment proof are unchanged.
use aegis_core::fronted_origin::{Gate, Settings};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

#[path = "fronted_forward.rs"]
pub(crate) mod forward;

pub(crate) struct FrontedOrigin {
    pub(crate) gate: Gate,
    pub(crate) forward: Option<forward::Forwarder>,
}

impl FrontedOrigin {
    pub(crate) fn load(settings: &Settings) -> anyhow::Result<Self> {
        let gate = Gate::load(settings)?;
        let forward = settings
            .enrollment_forward
            .as_ref()
            .map(forward::Forwarder::load)
            .transpose()?;
        Ok(Self { gate, forward })
    }
}

const MAX_HTTP1_HEADERS: usize = 8192;

/// HTTP/1.1 never carries the fronted tunnel. Read one bounded request head
/// and answer with the shared decoy, so the origin looks like a web server
/// rather than a raw TLS service on a direct probe.
pub(crate) async fn serve_http1_decoy<S>(stream: &mut S, seed: u16) -> anyhow::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut head = Vec::with_capacity(1024);
    while !head.windows(4).any(|w| w == b"\r\n\r\n") && head.len() < MAX_HTTP1_HEADERS {
        let mut chunk = [0u8; 1024];
        let cap = chunk.len().min(MAX_HTTP1_HEADERS - head.len());
        let count = stream.read(&mut chunk[..cap]).await?;
        if count == 0 {
            break;
        }
        head.extend_from_slice(&chunk[..count]);
    }
    let head_only = head.starts_with(b"HEAD ");
    super::decoy::write_http1(stream, seed, head_only).await?;
    stream.shutdown().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(extra: &str, fronted: &str) -> anyhow::Result<crate::config::ServerConfig> {
        let cfg: crate::config::ServerConfig = toml::from_str(&format!(
            r#"
listen = '127.0.0.1:0'
cert = '/etc/aegis/origin.pem'
key = '/etc/aegis/origin.key'
{extra}
[rate_limit]
trusted_proxy_cidrs = ['192.0.2.0/24']
[transport]
quic_required = false
[transport.inner_tls]
cert = '/etc/aegis/inner.pem'
key = '/etc/aegis/inner.key'
client_ca = '/etc/aegis/device-ca.pem'
[transport.fronted_origin]
authority = 'relay.example.test'
{fronted}
"#
        ))?;
        cfg.validate_auth_tokens()?;
        Ok(cfg)
    }

    #[test]
    fn fronted_origin_config_requires_an_exclusive_enrolled_cdn_origin() {
        let key = "credential_file = '/var/lib/aegis-relay/origin-pull.key'";
        assert!(config("", key).is_ok());
        // Shared tokens, open fallback and a bundle endpoint are refused.
        for extra in [
            "auth_token = '9cb2a1e3cb2bd80614253904098241f819eae687c4b0c15c30384a1dfa2e7189'",
            "fallback = 'proxy:127.0.0.1:8080'",
            "[bundle_endpoint]\nenabled = true",
        ] {
            assert!(config(extra, key).is_err(), "{extra}");
        }
        // The origin key must not reuse a TLS private key.
        assert!(config("", "credential_file = '/etc/aegis/origin.key'").is_err());
        assert!(config("", "credential_file = '/etc/aegis/inner.key'").is_err());
        assert!(config("", "credential_file = 'relative.key'").is_err());
        // QUIC and the HTTPS bridge are mutually exclusive with fronting.
        let quic: anyhow::Result<crate::config::ServerConfig> = (|| {
            let mut cfg = config("", key)?;
            cfg.transport.quic_required = true;
            cfg.validate_auth_tokens()?;
            Ok(cfg)
        })();
        assert!(quic.is_err());
        let no_proxies: anyhow::Result<()> = (|| {
            let mut cfg = config("", key)?;
            cfg.rate_limit.trusted_proxy_cidrs.clear();
            cfg.validate_auth_tokens()
        })();
        assert!(
            no_proxies.is_err(),
            "CDN client identity must come from trusted ranges"
        );
        let no_inner: anyhow::Result<()> = (|| {
            let mut cfg = config("", key)?;
            cfg.transport.inner_tls = None;
            cfg.validate_auth_tokens()
        })();
        assert!(
            no_inner.is_err(),
            "fronting never replaces device inner TLS"
        );
    }

    #[tokio::test]
    async fn http1_on_fronted_origin_is_a_bounded_decoy_not_a_tunnel() {
        for (request, head_only) in [
            (
                &b"GET / HTTP/1.1\r\nHost: relay.example.test\r\n\r\n"[..],
                false,
            ),
            (
                &b"HEAD /tunnel.v1.Channel/Connect HTTP/1.1\r\nHost: x\r\n\r\n"[..],
                true,
            ),
            (
                &b"GET /ws HTTP/1.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"[..],
                false,
            ),
        ] {
            let (mut client, mut server) = tokio::io::duplex(16 * 1024);
            let task = tokio::spawn(async move { serve_http1_decoy(&mut server, 443).await });
            client.write_all(request).await.unwrap();
            let mut reply = String::new();
            client.read_to_string(&mut reply).await.unwrap();
            task.await.unwrap().unwrap();
            assert!(reply.starts_with("HTTP/1.1 "), "{reply}");
            assert!(!reply.starts_with("HTTP/1.1 101"), "never an upgrade");
            assert!(!reply.starts_with("HTTP/1.1 200"), "never a tunnel");
            let body = reply.split_once("\r\n\r\n").unwrap().1;
            if head_only {
                assert!(body.is_empty());
            }
            assert!(!reply.to_ascii_lowercase().contains("aegis"));
        }
    }
}
