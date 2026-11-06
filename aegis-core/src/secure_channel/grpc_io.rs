//! Bounded uncompressed gRPC messages presented as a byte stream for TLS.

use std::io;
use std::pin::Pin;
use std::task::{ready, Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

const MAX_MESSAGE: usize = 64 * 1024;

pub struct GrpcIo<S> {
    stream: S,
    header: [u8; 5],
    header_read: usize,
    remaining: usize,
    pending: Vec<u8>,
    written: usize,
    shutdown: bool,
}

impl<S> GrpcIo<S> {
    pub fn new(stream: S) -> Self {
        Self {
            stream,
            header: [0; 5],
            header_read: 0,
            remaining: 0,
            pending: Vec::new(),
            written: 0,
            shutdown: false,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for GrpcIo<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if out.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        loop {
            if this.remaining > 0 {
                let take = out.remaining().min(this.remaining);
                let mut limited = ReadBuf::new(out.initialize_unfilled_to(take));
                ready!(Pin::new(&mut this.stream).poll_read(cx, &mut limited))?;
                let n = limited.filled().len();
                if n == 0 {
                    return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
                }
                out.advance(n);
                this.remaining -= n;
                return Poll::Ready(Ok(()));
            }
            while this.header_read < 5 {
                let mut buffer = ReadBuf::new(&mut this.header[this.header_read..]);
                ready!(Pin::new(&mut this.stream).poll_read(cx, &mut buffer))?;
                let n = buffer.filled().len();
                if n == 0 {
                    return if this.header_read == 0 {
                        Poll::Ready(Ok(()))
                    } else {
                        Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()))
                    };
                }
                this.header_read += n;
            }
            this.remaining = u32::from_be_bytes(this.header[1..5].try_into().unwrap()) as usize;
            this.header_read = 0;
            if this.header[0] != 0 || this.remaining > MAX_MESSAGE {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid secure gRPC message",
                )));
            }
            // Empty messages contain no TLS bytes; bound work per poll too.
            if this.remaining == 0 {
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
        }
    }
}

impl<S: AsyncWrite + Unpin> GrpcIo<S> {
    fn drain(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.written < self.pending.len() {
            let n =
                ready!(Pin::new(&mut self.stream).poll_write(cx, &self.pending[self.written..]))?;
            if n == 0 {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
            self.written += n;
        }
        self.pending.clear();
        self.written = 0;
        Poll::Ready(Ok(()))
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for GrpcIo<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.shutdown {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        if bytes.is_empty() {
            return Poll::Ready(Ok(0));
        }
        ready!(this.drain(cx))?;
        let n = bytes.len().min(MAX_MESSAGE);
        this.pending.push(0);
        this.pending.extend_from_slice(&(n as u32).to_be_bytes());
        this.pending.extend_from_slice(&bytes[..n]);
        // Accept exactly these bytes into the bounded buffer. flush/shutdown
        // drains it; a later Pending never refers to unacknowledged input.
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.drain(cx))?;
        Pin::new(&mut this.stream).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.shutdown {
            return Poll::Ready(Ok(()));
        }
        ready!(this.drain(cx))?;
        ready!(Pin::new(&mut this.stream).poll_shutdown(cx))?;
        this.shutdown = true;
        Poll::Ready(Ok(()))
    }
}
