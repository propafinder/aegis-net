use anyhow::Context;
use rustls::pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer};
use rustls::ServerConfig;
use std::fs::File;
use std::io::BufReader;
use std::path::Path;
use std::sync::Arc;

pub fn load_server_config(cert: &Path, key: &Path) -> anyhow::Result<Arc<ServerConfig>> {
    let cert_file = File::open(cert).with_context(|| format!("open {}", cert.display()))?;
    let key_bytes = aegis_core::secret_file::read_config(key, 1024 * 1024)
        .context("private_key_file_access_rejected")?;
    let mut cert_reader = BufReader::new(cert_file);
    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_reader_iter(&mut cert_reader)
        .collect::<Result<Vec<_>, _>>()
        .context("parse cert pem")?;
    let key = PrivateKeyDer::from_pem_slice(&key_bytes).context("read private key")?;
    let mut cfg = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("rustls server config")?;
    // Prefer h2 when a provider edge offers both protocols. Cloudflare gRPC
    // origin fetches need the relay to select h2, while bundle bootstrap keeps
    // using explicit HTTP/1.1.
    cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(Arc::new(cfg))
}
