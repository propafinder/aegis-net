//! Tokio owns the Winsock socket; memory BIOs carry ciphertext across the FFI
//! boundary. A SOCKET is pointer-sized and must never be cast to an OpenSSL fd.
use super::{RelaySettings, RelayTlsStream};
use anyhow::{ensure, Context};
use aws_lc_sys as ssl;
use std::{
    ffi::CString,
    io,
    path::Path,
    pin::Pin,
    ptr::NonNull,
    task::{ready, Context as TaskContext, Poll},
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::TcpStream,
};

#[cfg(test)]
mod tests;

struct ContextOwner(NonNull<ssl::SSL_CTX>);
impl Drop for ContextOwner {
    fn drop(&mut self) {
        unsafe { ssl::SSL_CTX_free(self.0.as_ptr()) }
    }
}
struct SslOwner(NonNull<ssl::SSL>);
impl Drop for SslOwner {
    fn drop(&mut self) {
        unsafe { ssl::SSL_free(self.0.as_ptr()) }
    }
}
struct BioOwner(NonNull<ssl::BIO>);
impl BioOwner {
    fn new() -> anyhow::Result<Self> {
        Ok(Self(
            NonNull::new(unsafe { ssl::BIO_new(ssl::BIO_s_mem()) })
                .context("allocate TLS memory BIO")?,
        ))
    }
}
impl Drop for BioOwner {
    fn drop(&mut self) {
        unsafe {
            ssl::BIO_free(self.0.as_ptr());
        }
    }
}

pub(crate) async fn connect_aws_lc_tls_with_alpn_protocols(
    settings: &RelaySettings,
    tcp: TcpStream,
    name: &str,
    alpn: &[Vec<u8>],
    sni: bool,
) -> anyhow::Result<(RelayTlsStream, Option<Vec<u8>>)> {
    let ech = aegis_client::ech_policy::effective_ech_config_list(settings)?;
    let mut stream = Stream::new(
        tcp,
        settings.ca_cert.as_deref(),
        name,
        alpn,
        sni,
        ech.as_deref(),
    )?;
    if let Err(error) = std::future::poll_fn(|cx| stream.poll_handshake(cx)).await {
        if let Some(rejected) = error.get_ref().and_then(|inner| {
            inner.downcast_ref::<aegis_client::ech_policy::AuthenticatedEchRetry>()
        }) {
            let rejected = aegis_client::ech_policy::AuthenticatedEchRetry {
                retry_configs: rejected.retry_configs.clone(),
            };
            let _ = aegis_client::ech_policy::record_rejection(settings, &rejected);
            return Err(rejected.into());
        }
        return Err(error.into());
    }
    let mut protocol = std::ptr::null();
    let mut length = 0;
    unsafe {
        ssl::SSL_get0_alpn_selected(stream.ssl.0.as_ptr(), &mut protocol, &mut length);
    }
    let alpn = if protocol.is_null() || length == 0 {
        None
    } else {
        Some(unsafe { std::slice::from_raw_parts(protocol, length as usize) }.to_vec())
    };
    Ok((Box::new(stream), alpn))
}

struct Stream {
    ssl: SslOwner,
    _ctx: ContextOwner,
    tcp: TcpStream,
    input: NonNull<ssl::BIO>,
    output: NonNull<ssl::BIO>,
    pending: Vec<u8>,
    offset: usize,
    eof: bool,
    shutdown_sent: bool,
    ech_required: bool,
}
// All SSL/BIO access is serialized through &mut Stream. The objects are never
// shared with another task; only immutable configuration is used after setup.
unsafe impl Send for Stream {}

impl Stream {
    fn new(
        tcp: TcpStream,
        ca: Option<&Path>,
        name: &str,
        alpn: &[Vec<u8>],
        sni: bool,
        ech: Option<&[u8]>,
    ) -> anyhow::Result<Self> {
        ssl::init();
        let ctx = ContextOwner(
            NonNull::new(unsafe { ssl::SSL_CTX_new(ssl::TLS_method()) })
                .context("create Windows TLS context")?,
        );
        unsafe {
            ssl::SSL_CTX_set_verify(ctx.0.as_ptr(), super::SSL_VERIFY_PEER, None);
            let tls = aegis_chrome_profile::chrome_stable();
            ssl::SSL_CTX_set_grease_enabled(ctx.0.as_ptr(), super::chrome_flag(tls.tls.grease));
            ssl::SSL_CTX_set_keylog_callback(ctx.0.as_ptr(), None);
            ssl::SSL_CTX_set_permute_extensions(
                ctx.0.as_ptr(),
                super::chrome_flag(tls.tls.permute_extensions),
            );
            super::configure_chrome_like_ciphers(ctx.0)?;
            super::configure_chrome_like_groups(ctx.0)?;
            super::configure_chrome_like_extensions(ctx.0)?;
            // Same omission policy as Unix TCP and QUIC: locked AWS-LC
            // appends custom TrustAnchorID outside the built-in permutation.
            aegis_quic_boring::config::windows_trust::load(ctx.0, ca, true)?;
            if !alpn.is_empty() {
                let wire = super::alpn_wire_protocols(alpn)?;
                ensure!(
                    ssl::SSL_CTX_set_alpn_protos(ctx.0.as_ptr(), wire.as_ptr(), wire.len()) == 0,
                    "set Windows TLS ALPN"
                );
            }
        }
        let ssl = SslOwner(
            NonNull::new(unsafe { ssl::SSL_new(ctx.0.as_ptr()) }).context("create TLS session")?,
        );
        let verify = CString::new(name).context("TLS name contains NUL")?;
        unsafe {
            ssl::SSL_set_mode(
                ssl.0.as_ptr(),
                ssl::SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER as u32,
            );
            super::configure_chrome_like_ssl_extensions(ssl.0, alpn, ech)?;
            if sni {
                ensure!(
                    ssl::SSL_set_tlsext_host_name(ssl.0.as_ptr(), verify.as_ptr()) == 1,
                    "set TLS server name"
                );
            }
            super::configure_name_verification(ssl.0, name, &verify)?;
        }
        let input = BioOwner::new()?;
        let output = BioOwner::new()?;
        unsafe {
            ssl::BIO_ctrl(
                input.0.as_ptr(),
                ssl::BIO_C_SET_BUF_MEM_EOF_RETURN,
                -1,
                std::ptr::null_mut(),
            );
            ssl::SSL_set_bio(ssl.0.as_ptr(), input.0.as_ptr(), output.0.as_ptr());
            ssl::SSL_set_connect_state(ssl.0.as_ptr());
        }
        let (input_ptr, output_ptr) = (input.0, output.0);
        // SSL_set_bio has taken ownership of both BIO references.
        std::mem::forget(input);
        std::mem::forget(output);
        Ok(Self {
            ssl,
            _ctx: ctx,
            tcp,
            input: input_ptr,
            output: output_ptr,
            pending: Vec::new(),
            offset: 0,
            eof: false,
            shutdown_sent: false,
            ech_required: ech.is_some(),
        })
    }

    fn error(&self, rc: i32) -> i32 {
        unsafe { ssl::SSL_get_error(self.ssl.0.as_ptr(), rc) }
    }
    fn failure(code: i32) -> io::Error {
        io::Error::other(format!(
            "Windows TLS operation failed: SSL_get_error={code}"
        ))
    }

    fn poll_output(&mut self, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        loop {
            while self.offset < self.pending.len() {
                let n =
                    ready!(Pin::new(&mut self.tcp).poll_write(cx, &self.pending[self.offset..]))?;
                if n == 0 {
                    return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
                }
                self.offset += n;
            }
            self.pending.clear();
            self.offset = 0;
            let pending = unsafe { ssl::BIO_pending(self.output.as_ptr()) };
            if pending == 0 {
                return Poll::Ready(Ok(()));
            }
            if pending > 1024 * 1024 {
                return Poll::Ready(Err(io::ErrorKind::InvalidData.into()));
            }
            self.pending.resize(pending.min(16 * 1024), 0);
            let n = unsafe {
                ssl::BIO_read(
                    self.output.as_ptr(),
                    self.pending.as_mut_ptr().cast(),
                    self.pending.len() as i32,
                )
            };
            if n <= 0 {
                return Poll::Ready(Err(io::ErrorKind::InvalidData.into()));
            }
            self.pending.truncate(n as usize);
        }
    }

    fn poll_input(&mut self, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        if self.eof {
            return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
        }
        if unsafe { ssl::BIO_pending(self.input.as_ptr()) } > 64 * 1024 {
            return Poll::Ready(Err(io::ErrorKind::InvalidData.into()));
        }
        let mut bytes = [0; 16 * 1024];
        let mut buf = ReadBuf::new(&mut bytes);
        ready!(Pin::new(&mut self.tcp).poll_read(cx, &mut buf))?;
        let bytes = buf.filled();
        if bytes.is_empty() {
            self.eof = true;
            return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
        }
        let n = unsafe {
            ssl::BIO_write(
                self.input.as_ptr(),
                bytes.as_ptr().cast(),
                bytes.len() as i32,
            )
        };
        if n as usize != bytes.len() {
            return Poll::Ready(Err(io::ErrorKind::InvalidData.into()));
        }
        Poll::Ready(Ok(()))
    }

    fn poll_handshake(&mut self, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        loop {
            ready!(self.poll_output(cx))?;
            let rc = unsafe {
                // OpenSSL's error queue is per OS thread; Tokio can resume a
                // different TLS session here after a peer failed verification.
                ssl::ERR_clear_error();
                ssl::SSL_do_handshake(self.ssl.0.as_ptr())
            };
            if rc == 1 {
                if self.ech_required && unsafe { ssl::SSL_ech_accepted(self.ssl.0.as_ptr()) } != 1 {
                    return Poll::Ready(Err(io::Error::other("required ECH was not accepted")));
                }
                return self.poll_output(cx);
            }
            match self.error(rc) {
                2 => {
                    ready!(self.poll_output(cx))?;
                    ready!(self.poll_input(cx))?;
                }
                3 => {
                    ready!(self.poll_output(cx))?;
                }
                code => {
                    if let Some(rejected) = super::ech_rejection(self.ssl.0.as_ptr()) {
                        return Poll::Ready(Err(io::Error::other(rejected)));
                    }
                    return Poll::Ready(Err(Self::failure(code)));
                }
            }
        }
    }
}

impl AsyncRead for Stream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        loop {
            // Make write progress, but never deadlock a full-duplex stream by
            // requiring a congested outbound socket to drain before reading.
            if let Poll::Ready(Err(error)) = this.poll_output(cx) {
                return Poll::Ready(Err(error));
            }
            let output = buf.initialize_unfilled();
            let rc = unsafe {
                ssl::ERR_clear_error();
                ssl::SSL_read(
                    this.ssl.0.as_ptr(),
                    output.as_mut_ptr().cast(),
                    output.len().min(16 * 1024) as i32,
                )
            };
            if rc > 0 {
                buf.advance(rc as usize);
                return Poll::Ready(Ok(()));
            }
            match this.error(rc) {
                2 => {
                    ready!(this.poll_input(cx))?;
                }
                3 => {
                    ready!(this.poll_output(cx))?;
                }
                6 => return Poll::Ready(Ok(())),
                code => return Poll::Ready(Err(Self::failure(code))),
            }
        }
    }
}

impl AsyncWrite for Stream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.shutdown_sent {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        if bytes.is_empty() {
            return Poll::Ready(Ok(0));
        }
        loop {
            ready!(this.poll_output(cx))?;
            let rc = unsafe {
                ssl::ERR_clear_error();
                ssl::SSL_write(
                    this.ssl.0.as_ptr(),
                    bytes.as_ptr().cast(),
                    bytes.len().min(16 * 1024) as i32,
                )
            };
            if rc > 0 {
                if let Poll::Ready(Err(error)) = this.poll_output(cx) {
                    return Poll::Ready(Err(error));
                }
                return Poll::Ready(Ok(rc as usize));
            }
            match this.error(rc) {
                2 => {
                    ready!(this.poll_input(cx))?;
                }
                3 => {
                    ready!(this.poll_output(cx))?;
                }
                code => return Poll::Ready(Err(Self::failure(code))),
            }
        }
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_output(cx))?;
        Pin::new(&mut this.tcp).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_output(cx))?;
        if !this.shutdown_sent {
            let rc = unsafe {
                ssl::ERR_clear_error();
                ssl::SSL_shutdown(this.ssl.0.as_ptr())
            };
            if rc < 0 {
                return Poll::Ready(Err(Self::failure(this.error(rc))));
            }
            this.shutdown_sent = true;
        }
        ready!(this.poll_output(cx))?;
        Pin::new(&mut this.tcp).poll_shutdown(cx)
    }
}
