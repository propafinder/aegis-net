//! Load Windows roots and Unicode CA paths without passing filenames through
//! the C runtime's ANSI fopen. Shared by the TCP and QUIC TLS backends.
use crate::Error;
use rustls_pki_types::{pem::PemObject, CertificateDer};
use std::{collections::HashSet, io::Read, path::Path, ptr::NonNull};

/// The caller owns the context and must not use it concurrently while loading.
/// # Safety
/// `ctx` must be a live, exclusively accessed SSL_CTX from this AWS-LC instance.
pub unsafe fn load(
    ctx: NonNull<aws_lc_sys::SSL_CTX>,
    ca: Option<&Path>,
    system: bool,
) -> Result<(), Error> {
    let mut certificates = Vec::new();
    if system {
        let roots = rustls_native_certs::load_native_certs();
        if roots.certs.is_empty() {
            return Err(Error::Ssl("Windows trust store has no usable certificates"));
        }
        certificates.extend(roots.certs);
    }
    if let Some(path) = ca {
        let file = std::fs::File::open(path).map_err(|_| Error::Ssl("open CA bundle"))?;
        let metadata = file.metadata().map_err(|_| Error::Ssl("CA metadata"))?;
        if !metadata.is_file() || metadata.len() > 4 * 1024 * 1024 {
            return Err(Error::Ssl("CA bundle size rejected"));
        }
        let mut bytes = Vec::new();
        file.take(4 * 1024 * 1024 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| Error::Ssl("read CA bundle"))?;
        if bytes.len() > 4 * 1024 * 1024 {
            return Err(Error::Ssl("CA bundle size rejected"));
        }
        let extra = CertificateDer::pem_slice_iter(&bytes)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| Error::Ssl("parse CA bundle"))?;
        if extra.is_empty() {
            return Err(Error::Ssl("CA bundle is empty"));
        }
        certificates.extend(extra);
    }
    let store = aws_lc_sys::SSL_CTX_get_cert_store(ctx.as_ptr());
    if store.is_null() {
        return Err(Error::Ssl("SSL_CTX certificate store missing"));
    }
    let mut seen = HashSet::new();
    for cert in certificates {
        if !seen.insert(cert.as_ref().to_vec()) {
            continue;
        }
        let mut input = cert.as_ptr();
        let parsed = aws_lc_sys::d2i_X509(std::ptr::null_mut(), &mut input, cert.len() as _);
        if parsed.is_null() {
            return Err(Error::Ssl("decode root certificate"));
        }
        let ok = aws_lc_sys::X509_STORE_add_cert(store, parsed);
        aws_lc_sys::X509_free(parsed);
        if ok != 1 {
            return Err(Error::Ssl("add root certificate"));
        }
    }
    Ok(())
}
