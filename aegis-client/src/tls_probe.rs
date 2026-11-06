use std::net::SocketAddr;

use aegis_core::{RelaySettings, RelayTlsBackend};
use clap::Args;
use serde_json::json;

#[derive(Args, Clone, Debug)]
pub(crate) struct TlsProbeArgs {
    /// TCP address to connect to (usually a local ClientHello capture listener).
    #[arg(long)]
    addr: SocketAddr,
    /// Hostname used for SNI and certificate-name verification.
    #[arg(long)]
    server_name: String,
    /// Relay TLS backend under measurement.
    #[arg(long, default_value = "rustls")]
    backend: String,
    /// Comma-separated ALPN protocols to advertise, in order.
    #[arg(long, default_value = "h2,http/1.1")]
    alpn: String,
    /// Disable SNI while keeping the verification name.
    #[arg(long)]
    disable_sni: bool,
    /// Emit a JSON result.
    #[arg(long)]
    json: bool,
    /// Additional CA bundle; certificate and hostname verification remain enabled.
    #[arg(long)]
    ca_cert: Option<std::path::PathBuf>,
    /// Return failure unless the TLS handshake actually completes.
    #[arg(long)]
    require_handshake: bool,
}

pub(crate) async fn run(args: &TlsProbeArgs) -> anyhow::Result<()> {
    let backend = parse_backend(&args.backend)?;
    let settings = RelaySettings {
        tls_backend: backend,
        ca_cert: args.ca_cert.clone(),
        ..Default::default()
    };
    let alpn_protocols = parse_alpn_protocols(&args.alpn)?;
    let handshake_error = crate::relay::diagnostic_tls_clienthello_probe(
        &settings,
        args.addr,
        &args.server_name,
        &alpn_protocols,
        !args.disable_sni,
    )
    .await?;

    let status = if handshake_error.is_some() {
        // ClientHello capture listeners intentionally close after the first TLS
        // record. The proof condition is the captured ClientHello bytes, not a
        // completed TLS session.
        "handshake_failed_after_clienthello_probe"
    } else {
        "handshake_completed"
    };

    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "status": status,
                "backend": backend.as_str(),
                "browser_identical_claimed": backend.browser_identical_claimed(),
                "addr": args.addr.to_string(),
                "server_name": args.server_name,
                "alpn": args.alpn,
                "sni_enabled": !args.disable_sni,
                "handshake_error": handshake_error,
            }))?
        );
    } else {
        println!("{status}");
    }
    if args.require_handshake && handshake_error.is_some() {
        anyhow::bail!("TLS handshake did not complete");
    }
    Ok(())
}

fn parse_backend(value: &str) -> anyhow::Result<RelayTlsBackend> {
    match value {
        "rustls" => Ok(RelayTlsBackend::Rustls),
        "chrome_like_experimental" => Ok(RelayTlsBackend::ChromeLikeExperimental),
        other => anyhow::bail!("unsupported relay TLS backend for probe: {other}"),
    }
}

fn parse_alpn_protocols(value: &str) -> anyhow::Result<Vec<Vec<u8>>> {
    let protocols = value
        .split(',')
        .map(str::trim)
        .filter(|proto| !proto.is_empty())
        .map(|proto| {
            anyhow::ensure!(
                proto.len() <= u8::MAX as usize,
                "ALPN protocol too long: {proto}"
            );
            Ok(proto.as_bytes().to_vec())
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    anyhow::ensure!(
        !protocols.is_empty(),
        "at least one ALPN protocol is required"
    );
    Ok(protocols)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_known_probe_backends() {
        assert_eq!(parse_backend("rustls").unwrap(), RelayTlsBackend::Rustls);
        assert_eq!(
            parse_backend("chrome_like_experimental").unwrap(),
            RelayTlsBackend::ChromeLikeExperimental
        );
    }

    #[test]
    fn rejects_unknown_probe_backend() {
        assert!(parse_backend("chrome").is_err());
    }

    #[test]
    fn parses_chrome_style_alpn_list() {
        assert_eq!(
            parse_alpn_protocols("h2,http/1.1").unwrap(),
            vec![b"h2".to_vec(), b"http/1.1".to_vec()]
        );
    }
}
