use super::RelayTlsStream;
use aegis_core::RelaySettings;
use anyhow::bail;
#[cfg(unix)]
use anyhow::Context;
use std::ffi::CString;
#[cfg(unix)]
use std::io;
use std::io::Read;
use std::net::IpAddr;
#[cfg(unix)]
use std::os::fd::AsRawFd;
#[cfg(unix)]
use std::os::unix::ffi::OsStrExt;
#[cfg(unix)]
use std::path::Path;
#[cfg(unix)]
use std::pin::Pin;
#[cfg(unix)]
use std::ptr;
use std::ptr::NonNull;
#[cfg(unix)]
use std::task::{ready, Context as TaskContext, Poll};
#[cfg(unix)]
use tokio::io::unix::AsyncFd;
#[cfg(unix)]
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
#[cfg(any(unix, test))]
use tokio::net::TcpStream;

#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub(crate) use windows::connect_aws_lc_tls_with_alpn_protocols;

#[cfg(all(test, unix))]
#[path = "aws_lc_setup_tests.rs"]
mod setup_tests;

#[cfg(unix)]
const SSL_ERROR_WANT_READ: i32 = 2;
#[cfg(unix)]
const SSL_ERROR_WANT_WRITE: i32 = 3;
#[cfg(unix)]
const SSL_ERROR_SYSCALL: i32 = 5;
#[cfg(unix)]
const SSL_ERROR_ZERO_RETURN: i32 = 6;
const SSL_VERIFY_PEER: i32 = 0x01;
const MAX_DECOMPRESSED_CERT_CHAIN: usize = 16 * 1024 * 1024;

#[cfg(test)]
pub(crate) async fn connect_aws_lc_tls(
    settings: &RelaySettings,
    tcp: TcpStream,
    verify_name: &str,
    alpn: Option<&[u8]>,
    enable_sni: bool,
) -> anyhow::Result<RelayTlsStream> {
    let protocols = alpn.map(|proto| vec![proto.to_vec()]).unwrap_or_default();
    connect_aws_lc_tls_with_alpn_protocols(settings, tcp, verify_name, &protocols, enable_sni)
        .await
        .map(|(stream, _alpn)| stream)
}

#[cfg(unix)]
pub(crate) async fn connect_aws_lc_tls_with_alpn_protocols(
    settings: &RelaySettings,
    tcp: TcpStream,
    verify_name: &str,
    alpn_protocols: &[Vec<u8>],
    enable_sni: bool,
) -> anyhow::Result<(RelayTlsStream, Option<Vec<u8>>)> {
    let std_tcp = tcp.into_std().context("convert relay tcp stream to std")?;
    std_tcp
        .set_nonblocking(true)
        .context("set aws-lc relay tcp nonblocking")?;
    let ech = aegis_client::ech_policy::effective_ech_config_list(settings)?;
    let mut stream = AwsLcTlsStream::new(
        std_tcp,
        settings.ca_cert.as_deref(),
        verify_name,
        alpn_protocols,
        enable_sni,
        ech.as_deref(),
    )?;
    if let Err(error) = stream.handshake().await {
        if let Some(rejected) =
            error.downcast_ref::<aegis_client::ech_policy::AuthenticatedEchRetry>()
        {
            let _ = aegis_client::ech_policy::record_rejection(settings, rejected);
        }
        return Err(error);
    }
    let alpn = stream.negotiated_alpn();
    Ok((Box::new(stream), alpn))
}

#[cfg(unix)]
struct ContextOwner(NonNull<aws_lc_sys::SSL_CTX>);

#[cfg(unix)]
impl ContextOwner {
    fn as_ptr(&self) -> *mut aws_lc_sys::SSL_CTX {
        self.0.as_ptr()
    }
}

#[cfg(unix)]
impl Drop for ContextOwner {
    fn drop(&mut self) {
        // SAFETY: this guard owns the SSL_CTX_new reference from allocation
        // through setup and, after transfer, for the stream's entire lifetime.
        unsafe { aws_lc_sys::SSL_CTX_free(self.as_ptr()) };
    }
}

#[cfg(unix)]
struct SslOwner(NonNull<aws_lc_sys::SSL>);

#[cfg(unix)]
impl SslOwner {
    fn as_ptr(&self) -> *mut aws_lc_sys::SSL {
        self.0.as_ptr()
    }
}

#[cfg(unix)]
impl Drop for SslOwner {
    fn drop(&mut self) {
        // SAFETY: this guard exclusively owns the SSL_new result and releases
        // it before its retained context. SSL_set_fd retains caller ownership
        // of the socket; SSL_free does not own or close that descriptor.
        unsafe { aws_lc_sys::SSL_free(self.as_ptr()) };
    }
}

#[cfg(unix)]
struct AwsLcTlsStream {
    // Fields drop in declaration order: SSL before its retained context and
    // socket, matching the former explicit stream Drop order.
    ssl: SslOwner,
    _ctx: ContextOwner,
    io: AsyncFd<std::net::TcpStream>,
    shutdown_sent: bool,
    ech_required: bool,
}

// The SSL object is only accessed through &mut self after construction. The fd
// is owned by AsyncFd and is not shared outside this stream.
#[cfg(unix)]
unsafe impl Send for AwsLcTlsStream {}

#[cfg(unix)]
impl AwsLcTlsStream {
    fn new(
        tcp: std::net::TcpStream,
        ca_cert: Option<&Path>,
        verify_name: &str,
        alpn_protocols: &[Vec<u8>],
        enable_sni: bool,
        ech_config_list: Option<&[u8]>,
    ) -> anyhow::Result<Self> {
        aws_lc_sys::init();
        let ctx = ContextOwner(unsafe {
            let method = aws_lc_sys::TLS_method();
            if method.is_null() {
                bail!("aws-lc TLS_method returned null");
            }
            NonNull::new(aws_lc_sys::SSL_CTX_new(method))
                .ok_or_else(|| anyhow::anyhow!("aws-lc SSL_CTX_new failed"))?
        });
        #[cfg(test)]
        setup_tests::observe_context(ctx.0);

        let ssl = unsafe {
            aws_lc_sys::SSL_CTX_set_verify(ctx.as_ptr(), SSL_VERIFY_PEER, None);
            let tls = &aegis_chrome_profile::chrome_stable().tls;
            aws_lc_sys::SSL_CTX_set_grease_enabled(ctx.as_ptr(), chrome_flag(tls.grease));
            // No key-log callback: inherited environment variables must not
            // turn a production connection into a traffic-secret exporter.
            aws_lc_sys::SSL_CTX_set_keylog_callback(ctx.as_ptr(), None);
            aws_lc_sys::SSL_CTX_set_permute_extensions(
                ctx.as_ptr(),
                chrome_flag(tls.permute_extensions),
            );
            configure_chrome_like_ciphers(ctx.0)?;
            configure_chrome_like_groups(ctx.0)?;
            configure_chrome_like_extensions(ctx.0)?;
            if aws_lc_sys::SSL_CTX_set_default_verify_paths(ctx.as_ptr()) != 1 {
                bail!("aws-lc default verify paths unavailable");
            }
            if let Some(ca_cert) = ca_cert {
                let ca = cstring_path(ca_cert)?;
                if aws_lc_sys::SSL_CTX_load_verify_locations(ctx.as_ptr(), ca.as_ptr(), ptr::null())
                    != 1
                {
                    bail!("aws-lc load ca_cert failed");
                }
            }
            if !alpn_protocols.is_empty() {
                let wire = alpn_wire_protocols(alpn_protocols)?;
                if aws_lc_sys::SSL_CTX_set_alpn_protos(ctx.as_ptr(), wire.as_ptr(), wire.len()) != 0
                {
                    bail!("aws-lc set ALPN failed");
                }
            }

            let ssl = SslOwner(
                NonNull::new(aws_lc_sys::SSL_new(ctx.as_ptr()))
                    .ok_or_else(|| anyhow::anyhow!("aws-lc SSL_new failed"))?,
            );
            #[cfg(test)]
            setup_tests::observe_ssl(ssl.0);
            configure_chrome_like_ssl_extensions(ssl.0, alpn_protocols, ech_config_list)?;
            let verify = CString::new(verify_name).context("tls verify name contains NUL")?;
            if enable_sni
                && aws_lc_sys::SSL_set_tlsext_host_name(ssl.as_ptr(), verify.as_ptr()) != 1
            {
                bail!("aws-lc set SNI failed");
            }
            configure_name_verification(ssl.0, verify_name, &verify)?;
            if aws_lc_sys::SSL_set_fd(ssl.as_ptr(), tcp.as_raw_fd()) != 1 {
                bail!("aws-lc SSL_set_fd failed");
            }
            ssl
        };

        #[cfg(test)]
        setup_tests::before_io_registration()?;
        // SAFETY: AsyncFd owns tcp and its descriptor stays open and unchanged
        // until AsyncFd is dropped. SSL borrows the descriptor without closing
        // it, and the SSL owner is dropped before io.
        let io = unsafe { AsyncFd::register(tcp) }.context("create aws-lc relay AsyncFd")?;
        Ok(Self {
            ssl,
            _ctx: ctx,
            io,
            shutdown_sent: false,
            ech_required: ech_config_list.is_some(),
        })
    }

    async fn handshake(&mut self) -> anyhow::Result<()> {
        loop {
            let rc = unsafe { aws_lc_sys::SSL_connect(self.ssl.as_ptr()) };
            if rc == 1 {
                if self.ech_required
                    && unsafe { aws_lc_sys::SSL_ech_accepted(self.ssl.as_ptr()) } != 1
                {
                    bail!("required ECH was not accepted");
                }
                return Ok(());
            }
            match self.ssl_error(rc) {
                SSL_ERROR_WANT_READ => {
                    let mut guard = self.io.readable().await.context("aws-lc tls readable")?;
                    guard.clear_ready();
                }
                SSL_ERROR_WANT_WRITE => {
                    let mut guard = self.io.writable().await.context("aws-lc tls writable")?;
                    guard.clear_ready();
                }
                err => {
                    if let Some(rejected) = ech_rejection(self.ssl.as_ptr()) {
                        return Err(rejected.into());
                    }
                    bail!("aws-lc TLS handshake failed: SSL_get_error={err}")
                }
            }
        }
    }

    /// The ALPN protocol the server picked, if any.
    ///
    /// The https_ws transport needs this: with RFC 8441 it offers Chrome's
    /// `h2,http/1.1` and must then speak whichever the relay chose, rather
    /// than assuming http/1.1 the way the HTTP/1.1-Upgrade-only path could.
    fn negotiated_alpn(&self) -> Option<Vec<u8>> {
        unsafe {
            let mut data: *const u8 = std::ptr::null();
            let mut len: u32 = 0;
            aws_lc_sys::SSL_get0_alpn_selected(self.ssl.as_ptr(), &mut data, &mut len);
            if data.is_null() || len == 0 {
                return None;
            }
            Some(std::slice::from_raw_parts(data, len as usize).to_vec())
        }
    }

    fn ssl_error(&self, rc: i32) -> i32 {
        unsafe { aws_lc_sys::SSL_get_error(self.ssl.as_ptr(), rc) }
    }
}

#[cfg(unix)]
impl AsyncRead for AwsLcTlsStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        let mut want_write = false;
        loop {
            let mut guard = if want_write {
                ready!(this.io.poll_write_ready(cx))?
            } else {
                ready!(this.io.poll_read_ready(cx))?
            };
            let rc = unsafe {
                aws_lc_sys::SSL_read(
                    this.ssl.as_ptr(),
                    buf.unfilled_mut().as_mut_ptr().cast(),
                    buf.remaining().min(i32::MAX as usize) as i32,
                )
            };
            if rc > 0 {
                let n = rc as usize;
                unsafe {
                    buf.assume_init(n);
                }
                buf.advance(n);
                return Poll::Ready(Ok(()));
            }
            match this.ssl_error(rc) {
                SSL_ERROR_WANT_READ => {
                    want_write = false;
                    guard.clear_ready();
                }
                SSL_ERROR_WANT_WRITE => {
                    want_write = true;
                    guard.clear_ready();
                }
                SSL_ERROR_ZERO_RETURN => return Poll::Ready(Ok(())),
                SSL_ERROR_SYSCALL if rc == 0 => return Poll::Ready(Ok(())),
                err => {
                    return Poll::Ready(Err(io::Error::other(format!(
                        "aws-lc SSL_read failed: SSL_get_error={err}"
                    ))));
                }
            }
        }
    }
}

#[cfg(unix)]
impl AsyncWrite for AwsLcTlsStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if data.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if this.shutdown_sent {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        let mut want_read = false;
        loop {
            let mut guard = if want_read {
                ready!(this.io.poll_read_ready(cx))?
            } else {
                ready!(this.io.poll_write_ready(cx))?
            };
            let rc = unsafe {
                aws_lc_sys::SSL_write(
                    this.ssl.as_ptr(),
                    data.as_ptr().cast(),
                    data.len().min(i32::MAX as usize) as i32,
                )
            };
            if rc > 0 {
                return Poll::Ready(Ok(rc as usize));
            }
            match this.ssl_error(rc) {
                SSL_ERROR_WANT_READ => {
                    want_read = true;
                    guard.clear_ready();
                }
                SSL_ERROR_WANT_WRITE => {
                    want_read = false;
                    guard.clear_ready();
                }
                err => {
                    return Poll::Ready(Err(io::Error::other(format!(
                        "aws-lc SSL_write failed: SSL_get_error={err}"
                    ))));
                }
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.shutdown_sent {
            return Poll::Ready(Ok(()));
        }
        loop {
            let rc = unsafe { aws_lc_sys::SSL_shutdown(this.ssl.as_ptr()) };
            // Both 0 and 1 mean our close_notify was sent. Do not wait for the
            // peer's close_notify: it may first send a response to our EOF.
            // Repeated shutdown must not consume that application response.
            if rc >= 0 {
                this.shutdown_sent = true;
                return Poll::Ready(Ok(()));
            }
            match this.ssl_error(rc) {
                SSL_ERROR_WANT_READ => {
                    ready!(this.io.poll_read_ready(cx))?.clear_ready();
                }
                SSL_ERROR_WANT_WRITE => {
                    ready!(this.io.poll_write_ready(cx))?.clear_ready();
                }
                err => {
                    return Poll::Ready(Err(io::Error::other(format!(
                        "aws-lc SSL_shutdown failed: SSL_get_error={err}"
                    ))));
                }
            }
        }
    }
}

#[cfg(test)]
fn alpn_wire(proto: &[u8]) -> anyhow::Result<Vec<u8>> {
    alpn_wire_protocols(&[proto.to_vec()])
}

fn alpn_wire_protocols(protocols: &[Vec<u8>]) -> anyhow::Result<Vec<u8>> {
    anyhow::ensure!(!protocols.is_empty(), "ALPN protocol list cannot be empty");
    let mut wire = Vec::new();
    for proto in protocols {
        wire.extend_from_slice(&alpn_wire_one(proto)?);
    }
    Ok(wire)
}

fn alpn_wire_one(proto: &[u8]) -> anyhow::Result<Vec<u8>> {
    anyhow::ensure!(!proto.is_empty(), "ALPN protocol cannot be empty");
    anyhow::ensure!(proto.len() <= u8::MAX as usize, "ALPN protocol too long");
    let mut wire = Vec::with_capacity(proto.len() + 1);
    wire.push(proto.len() as u8);
    wire.extend_from_slice(proto);
    Ok(wire)
}

fn ech_rejection(
    ssl: *mut aws_lc_sys::SSL,
) -> Option<aegis_client::ech_policy::AuthenticatedEchRetry> {
    unsafe {
        let packed = aws_lc_sys::ERR_peek_error();
        if packed == 0 || aws_lc_sys::ERR_GET_REASON(packed as u32) != 319 {
            return None;
        }
        let mut ptr: *const u8 = std::ptr::null();
        let mut len = 0usize;
        aws_lc_sys::SSL_get0_ech_retry_configs(ssl, &mut ptr, &mut len);
        let retry_configs = if ptr.is_null() || len == 0 {
            None
        } else {
            Some(std::slice::from_raw_parts(ptr, len).to_vec())
        };
        Some(aegis_client::ech_policy::AuthenticatedEchRetry { retry_configs })
    }
}

fn chrome_flag(enabled: bool) -> i32 {
    if enabled {
        1
    } else {
        0
    }
}

unsafe fn configure_chrome_like_ciphers(ctx: NonNull<aws_lc_sys::SSL_CTX>) -> anyhow::Result<()> {
    let tls = &aegis_chrome_profile::chrome_stable().tls;
    let tls13 = CString::new(tls.tls13_cipher_string()).expect("TLS 1.3 cipher list has no NUL");
    if aws_lc_sys::SSL_CTX_set_ciphersuites(ctx.as_ptr(), tls13.as_ptr()) != 1 {
        bail!("aws-lc set Chrome-like TLS 1.3 ciphers failed");
    }
    let tls12 = CString::new(tls.tls12_cipher_string()).expect("TLS 1.2 cipher list has no NUL");
    if aws_lc_sys::SSL_CTX_set_strict_cipher_list(ctx.as_ptr(), tls12.as_ptr()) != 1 {
        bail!("aws-lc set Chrome-like TLS 1.2 ciphers failed");
    }
    Ok(())
}

unsafe fn configure_chrome_like_groups(ctx: NonNull<aws_lc_sys::SSL_CTX>) -> anyhow::Result<()> {
    let groups = CString::new(aegis_chrome_profile::chrome_stable().tls.groups_string())
        .expect("group list has no NUL");
    if aws_lc_sys::SSL_CTX_set1_groups_list(ctx.as_ptr(), groups.as_ptr()) != 1 {
        bail!("aws-lc set Chrome-like supported groups failed");
    }
    Ok(())
}

unsafe fn configure_chrome_like_extensions(
    ctx: NonNull<aws_lc_sys::SSL_CTX>,
) -> anyhow::Result<()> {
    let tls = aegis_chrome_profile::chrome_stable().tls.clone();
    if tls.ocsp_stapling {
        aws_lc_sys::SSL_CTX_enable_ocsp_stapling(ctx.as_ptr());
    }
    if tls.signed_cert_timestamps {
        aws_lc_sys::SSL_CTX_enable_signed_cert_timestamps(ctx.as_ptr());
    }
    if tls.cert_compression.iter().any(|name| name == "brotli")
        && aws_lc_sys::SSL_CTX_add_cert_compression_alg(
            ctx.as_ptr(),
            aws_lc_sys::TLSEXT_cert_compression_brotli as u16,
            None,
            Some(brotli_cert_decompress),
        ) != 1
    {
        bail!("aws-lc enable brotli certificate decompression failed");
    }

    // signature_algorithms, in Chrome's order.
    //
    // Measured against live Google Chrome 151 (Linux x86_64) on 2026-08-10 by
    // capturing both ClientHellos and running the SAME tshark over each:
    //
    //   chrome : t13d1516h2_8daaf6152771_806a8c22fdea
    //   aegis  : t13d1516h2_8daaf6152771_d8a2da3f94cd
    //
    // Head and cipher hash were byte-identical; only the third component
    // differed, and `tls.handshake.ja4_r` narrowed it to exactly this list.
    // Chrome leads with three ML-DSA post-quantum schemes (0x0904, 0x0905,
    // 0x0906) that we did not advertise:
    //
    //   chrome: 0904,0905,0906,0403,0804,0401,0503,0805,0501,0806,0601
    //   aegis :           0403,0804,0401,0503,0805,0501,0806,0601
    //
    // Canonical JA4 folds signature_algorithms into its third hash, so those
    // three missing code points alone made every AEGIS ClientHello
    // distinguishable from Chrome to anything doing standard JA4 matching.
    //
    // This survived the existing parity contract because that harness computes
    // its own cipher/extension hashes and never looks at signature algorithms
    // — it reported ACHIEVED while the canonical fingerprint did not match.
    //
    // The order matters: JA4 hashes signature_algorithms as sent, not sorted.
    // Refresh from a live capture when Chrome's list changes; see
    // scripts/test-chrome-like-tls-ja4-parity-contract.sh.
    // signature_algorithms, in Chrome's order, matching live Chrome 151.
    //
    // Chrome leads with three ML-DSA post-quantum schemes. They are not
    // cosmetic: canonical JA4 folds signature_algorithms into its third
    // component, so omitting them made every AEGIS ClientHello distinguishable
    // from Chrome to standard JA4 matching, even though the cipher list and
    // the extension list matched byte for byte.
    //
    //   before: t13d1516h2_8daaf6152771_d8a2da3f94cd
    //   chrome: t13d1516h2_8daaf6152771_806a8c22fdea
    //
    // aws-lc-sys 0.39.1 could not express this: get_signature_algorithm()
    // returned null for 0x0904, SSL_CTX_set_verify_algorithm_prefs failed, and
    // this function bailed BEFORE the ClientHello was written — the failure
    // mode was an empty connection, not a fallback. 0.44.0 defines
    // SSL_SIGN_MLDSA44/65/87 and accepts them.
    //
    // Order matters: JA4 hashes this list as sent, not sorted. Refresh from a
    // live capture when Chrome's list changes —
    // scripts/test-chrome-canonical-ja4-parity-contract.sh compares against a
    // captured Chrome ClientHello, not against a hand-maintained constant.
    let verify_sigalgs = tls.signature_algorithms;
    if aws_lc_sys::SSL_CTX_set_verify_algorithm_prefs(
        ctx.as_ptr(),
        verify_sigalgs.as_ptr(),
        verify_sigalgs.len(),
    ) != 1
    {
        bail!("aws-lc set Chrome-like signature algorithms failed");
    }

    Ok(())
}

unsafe extern "C" fn brotli_cert_decompress(
    _ssl: *mut aws_lc_sys::SSL,
    out: *mut *mut aws_lc_sys::CRYPTO_BUFFER,
    uncompressed_len: usize,
    input: *const u8,
    input_len: usize,
) -> std::os::raw::c_int {
    if out.is_null()
        || input.is_null()
        || uncompressed_len == 0
        || uncompressed_len > MAX_DECOMPRESSED_CERT_CHAIN
    {
        return 0;
    }

    let compressed = std::slice::from_raw_parts(input, input_len);
    let mut decoder = brotli::Decompressor::new(std::io::Cursor::new(compressed), 4096)
        .take((uncompressed_len as u64).saturating_add(1));
    let mut decompressed = Vec::with_capacity(uncompressed_len.min(64 * 1024));
    if decoder.read_to_end(&mut decompressed).is_err() || decompressed.len() != uncompressed_len {
        return 0;
    }

    let buffer = aws_lc_sys::CRYPTO_BUFFER_new(
        decompressed.as_ptr(),
        decompressed.len(),
        std::ptr::null_mut(),
    );
    if buffer.is_null() {
        return 0;
    }

    *out = buffer;
    1
}

pub(super) unsafe fn configure_chrome_like_ssl_extensions(
    ssl: NonNull<aws_lc_sys::SSL>,
    alpn_protocols: &[Vec<u8>],
    ech_config_list: Option<&[u8]>,
) -> anyhow::Result<()> {
    let tls = &aegis_chrome_profile::chrome_stable().tls;
    if let Some(list) = ech_config_list {
        anyhow::ensure!(!list.is_empty(), "ECH config list is empty");
        if aws_lc_sys::SSL_set1_ech_config_list(ssl.as_ptr(), list.as_ptr(), list.len()) != 1 {
            bail!("aws-lc rejected the ECH config list");
        }
    } else if tls.ech_grease {
        aws_lc_sys::SSL_set_enable_ech_grease(ssl.as_ptr(), 1);
    }

    if tls.alps_new_codepoint && alpn_protocols.iter().any(|proto| proto.as_slice() == b"h2") {
        aws_lc_sys::SSL_set_alps_use_new_codepoint(ssl.as_ptr(), 1);
        let settings: [u8; 0] = [];
        if aws_lc_sys::SSL_add_application_settings(
            ssl.as_ptr(),
            b"h2".as_ptr(),
            b"h2".len(),
            settings.as_ptr(),
            settings.len(),
        ) != 1
        {
            bail!("aws-lc enable Chrome-like ALPS failed");
        }
    }

    Ok(())
}

#[cfg(unix)]
fn cstring_path(path: &Path) -> anyhow::Result<CString> {
    CString::new(path.as_os_str().as_bytes()).context("path contains NUL")
}

unsafe fn configure_name_verification(
    ssl: NonNull<aws_lc_sys::SSL>,
    verify_name: &str,
    verify: &CString,
) -> anyhow::Result<()> {
    if verify_name.parse::<IpAddr>().is_ok() {
        let param = aws_lc_sys::SSL_get0_param(ssl.as_ptr());
        if param.is_null() {
            bail!("aws-lc SSL_get0_param returned null");
        }
        if aws_lc_sys::X509_VERIFY_PARAM_set1_ip_asc(param, verify.as_ptr()) != 1 {
            bail!("aws-lc set IP verification failed");
        }
    } else if aws_lc_sys::SSL_set1_host(ssl.as_ptr(), verify.as_ptr()) != 1 {
        bail!("aws-lc set hostname verification failed");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{alpn_wire, connect_aws_lc_tls};
    use aegis_core::RelaySettings;
    use rcgen::{generate_simple_self_signed, CertifiedKey};
    use std::fs;
    use std::sync::Arc;
    use std::time::{SystemTime, UNIX_EPOCH};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn alpn_wire_encodes_single_protocol() {
        assert_eq!(alpn_wire(b"h2").unwrap(), vec![2, b'h', b'2']);
        assert_eq!(
            alpn_wire(b"http/1.1").unwrap(),
            vec![8, b'h', b't', b't', b'p', b'/', b'1', b'.', b'1']
        );
    }

    /// Capture only the actual production adapter's first flight. The owned
    /// loopback peer closes without completing TLS; this is wire-shape evidence,
    /// not certificate acceptance or comparison with a live browser.
    #[tokio::test]
    async fn actual_tcp_first_flight_omits_custom_trust_anchor_hint() {
        use aegis_quic_boring::fingerprint::clienthello::{ext, parse};
        use std::time::Duration;
        use tokio::net::{TcpListener, TcpStream};

        tokio::time::timeout(Duration::from_secs(10), async {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let capture = async {
                let (mut tcp, _) = listener.accept().await.unwrap();
                let mut header = [0; 5];
                tcp.read_exact(&mut header).await.unwrap();
                assert_eq!(header[0], 22, "first record must carry a handshake");
                let length = u16::from_be_bytes([header[3], header[4]]) as usize;
                assert!(length > 0 && length < 16384);
                let mut record = vec![0; length];
                tcp.read_exact(&mut record).await.unwrap();
                record
            };
            let client = async {
                let tcp = TcpStream::connect(address).await.unwrap();
                connect_aws_lc_tls(
                    &RelaySettings::default(),
                    tcp,
                    "example.com",
                    Some(b"h2"),
                    true,
                )
                .await
            };
            // Both futures remain owned here. Timeout drops their sockets and
            // SSL owners; no detached client task survives a failed capture.
            let (record, result) = tokio::join!(capture, client);
            assert!(result.is_err(), "capture peer did not complete TLS");
            let hello = parse(&record).unwrap();
            let profile = aegis_chrome_profile::chrome_stable();
            let tls13 = profile
                .tls
                .tls13_ciphers
                .iter()
                .map(|name| aegis_chrome_profile::cipher_id(name).unwrap())
                .collect::<Vec<_>>();
            let tls12 = profile
                .tls
                .tls12_ciphers
                .iter()
                .map(|name| aegis_chrome_profile::cipher_id(name).unwrap())
                .collect::<Vec<_>>();
            let mut ciphers = tls13;
            ciphers.extend(tls12);
            assert_eq!(hello.real_cipher_suites(), ciphers);
            let groups = profile
                .tls
                .groups
                .iter()
                .map(|name| aegis_chrome_profile::group_id(name).unwrap())
                .collect::<Vec<_>>();
            let offered_groups = hello
                .supported_groups
                .iter()
                .copied()
                .filter(|group| !aegis_quic_boring::fingerprint::clienthello::is_grease(*group))
                .collect::<Vec<_>>();
            assert_eq!(offered_groups, groups);
            assert_eq!(hello.signature_algorithms, profile.tls.signature_algorithms);
            assert_eq!(hello.uses_grease(), profile.tls.grease);
            assert_eq!(hello.max_version(), 0x0304);
            assert_eq!(hello.server_name.as_deref(), Some("example.com"));
            assert_eq!(hello.alpn, vec![b"h2".to_vec()]);
            assert!(!hello.has_extension(ext::QUIC_TRANSPORT_PARAMETERS));
            assert!(
                !hello.has_extension(0xca34),
                "custom TrustAnchorID must be omitted on every platform"
            );
        })
        .await
        .expect("actual TCP first-flight capture deadline");
    }

    /// One structurally valid ECHConfig. Rustls accepts every KEM below;
    /// AWS-LC's client offers only DHKEM(X25519, HKDF-SHA256).
    fn ech_list_with_kem(kem: u16, key_len: usize) -> Vec<u8> {
        let mut contents = vec![7];
        contents.extend(kem.to_be_bytes());
        contents.extend((key_len as u16).to_be_bytes());
        let mut key = vec![4u8; key_len];
        key[0] = if key_len == 32 { 9 } else { 4 };
        contents.extend(key);
        contents.extend([0, 4, 0, 1, 0, 1, 0]);
        contents.push(b"cover.example".len() as u8);
        contents.extend(b"cover.example");
        contents.extend([0, 0]);
        let mut config = vec![0xfe, 0x0d];
        config.extend((contents.len() as u16).to_be_bytes());
        config.extend(contents);
        let mut list = (config.len() as u16).to_be_bytes().to_vec();
        list.extend(config);
        list
    }

    /// A pinned ECH list that rustls accepts but AWS-LC cannot use made
    /// AWS-LC proceed without ECH: the first flight carried the inner name in
    /// a cleartext SNI, and only the post-handshake SSL_ech_accepted check
    /// failed the connection. Nothing may reach the wire in that case.
    #[tokio::test]
    async fn ech_list_aws_lc_cannot_offer_sends_no_client_hello() {
        use base64::Engine;
        use std::time::Duration;
        use tokio::net::{TcpListener, TcpStream};

        // DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, AES-128-GCM.
        let list = ech_list_with_kem(0x0010, 65);
        aegis_client::ech_policy::inline_ech_config(
            &base64::engine::general_purpose::STANDARD.encode(&list),
        )
        .expect("rustls admits the P-256 config, so profile validation passes");
        let settings = RelaySettings {
            server_name: "example.com".into(),
            ech_config_list_base64: Some(base64::engine::general_purpose::STANDARD.encode(&list)),
            ..RelaySettings::default()
        };

        tokio::time::timeout(Duration::from_secs(10), async {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let capture = async {
                let (mut tcp, _) = listener.accept().await.unwrap();
                let mut first = vec![0; 16 * 1024];
                let n = match tokio::time::timeout(Duration::from_secs(3), tcp.read(&mut first))
                    .await
                {
                    Ok(Ok(n)) => n,
                    _ => 0,
                };
                first.truncate(n);
                first
            };
            let client = async {
                let tcp = TcpStream::connect(address).await.unwrap();
                connect_aws_lc_tls(&settings, tcp, "example.com", Some(b"h2"), true).await
            };
            let (first, result) = tokio::join!(capture, client);
            assert!(result.is_err(), "unusable required ECH must not connect");
            let leaked = (first.len() > 5)
                .then(|| aegis_quic_boring::fingerprint::clienthello::parse(&first[5..]).ok())
                .flatten()
                .and_then(|hello| hello.server_name);
            assert!(
                first.is_empty(),
                "{} bytes reached the wire; cleartext SNI {leaked:?}",
                first.len()
            );
        })
        .await
        .expect("ECH refusal deadline");

        // The supported shape still reaches the wire, as ECH.
        let usable = ech_list_with_kem(0x0020, 32);
        let settings = RelaySettings {
            server_name: "example.com".into(),
            ech_config_list_base64: Some(base64::engine::general_purpose::STANDARD.encode(&usable)),
            ..RelaySettings::default()
        };
        tokio::time::timeout(Duration::from_secs(10), async {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let capture = async {
                let (mut tcp, _) = listener.accept().await.unwrap();
                let mut header = [0; 5];
                tcp.read_exact(&mut header).await.unwrap();
                let length = u16::from_be_bytes([header[3], header[4]]) as usize;
                let mut record = vec![0; length];
                tcp.read_exact(&mut record).await.unwrap();
                record
            };
            let client = async {
                let tcp = TcpStream::connect(address).await.unwrap();
                connect_aws_lc_tls(&settings, tcp, "example.com", Some(b"h2"), true).await
            };
            let (record, result) = tokio::join!(capture, client);
            assert!(result.is_err(), "capture peer did not complete TLS");
            let hello = aegis_quic_boring::fingerprint::clienthello::parse(&record).unwrap();
            assert!(hello.has_extension(0xfe0d), "ECH extension offered");
            assert_eq!(
                hello.server_name.as_deref(),
                Some("cover.example"),
                "outer SNI is the ECH public name"
            );
        })
        .await
        .expect("usable ECH capture deadline");
    }

    #[tokio::test]
    async fn aws_lc_backend_completes_local_tls_roundtrip() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let CertifiedKey { cert, key_pair } =
            generate_simple_self_signed(vec!["localhost".into()]).expect("rcgen");
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("aegis-aws-lc-tls-test-{unique}"));
        fs::create_dir_all(&dir).expect("create temp cert dir");
        let cert_path = dir.join("cert.pem");
        let cert_pem = cert.pem();
        fs::write(&cert_path, &cert_pem).expect("write cert pem");

        let mut cert_rd = std::io::BufReader::new(cert_pem.as_bytes());
        use rustls::pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer};

        let certs = CertificateDer::pem_reader_iter(&mut cert_rd)
            .collect::<Result<Vec<_>, _>>()
            .expect("parse cert pem");
        let key_pem = key_pair.serialize_pem();
        let mut key_rd = std::io::BufReader::new(key_pem.as_bytes());
        let key = PrivateKeyDer::from_pem_reader(&mut key_rd).expect("parse key");
        let server_cfg = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .expect("server config");
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_cfg));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind listener");
        let addr = listener.local_addr().expect("listener addr");
        let server = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.expect("accept tcp");
            let mut tls = acceptor.accept(tcp).await.expect("accept tls");
            let mut got = [0u8; 4];
            tls.read_exact(&mut got).await.expect("read ping");
            assert_eq!(&got, b"ping");
            tls.write_all(b"pong").await.expect("write pong");
        });

        let tcp = tokio::net::TcpStream::connect(addr).await.expect("connect");
        let settings = RelaySettings {
            ca_cert: Some(cert_path.clone()),
            ..Default::default()
        };
        let mut tls = connect_aws_lc_tls(&settings, tcp, "localhost", Some(b"http/1.1"), true)
            .await
            .expect("aws-lc connect");
        tls.write_all(b"ping").await.expect("write ping");
        let mut got = [0u8; 4];
        tls.read_exact(&mut got).await.expect("read pong");
        assert_eq!(&got, b"pong");
        server.await.expect("server task");

        let _ = fs::remove_dir_all(&dir);
    }
}
