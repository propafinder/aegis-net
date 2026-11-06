//! Bounded WebSocket binary messages exposed as an opaque byte stream.
//! The bytes are the existing device-authenticated TLS protocol, never a
//! WebSocket-specific token or target request.

use futures::{ready, Sink, Stream};
use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_tungstenite::{tungstenite::Message, WebSocketStream};

const MAX_WRITE: usize = 16 * 1024;
const MAX_READ: usize = 1024 * 1024;

pub fn bounded_config() -> tokio_tungstenite::tungstenite::protocol::WebSocketConfig {
    tokio_tungstenite::tungstenite::protocol::WebSocketConfig {
        max_message_size: Some(MAX_READ),
        max_frame_size: Some(MAX_READ),
        max_write_buffer_size: MAX_READ * 2,
        ..Default::default()
    }
}

pub struct WsIo<S> {
    ws: WebSocketStream<S>,
    read: Vec<u8>,
    offset: usize,
    read_closed: bool,
    write_closed: bool,
    wire_closed: bool,
}

impl<S> WsIo<S> {
    pub fn new(ws: WebSocketStream<S>) -> Self {
        Self {
            ws,
            read: Vec::new(),
            offset: 0,
            read_closed: false,
            write_closed: false,
            wire_closed: false,
        }
    }
}

fn ws_error(error: tokio_tungstenite::tungstenite::Error) -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, error)
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for WsIo<S> {
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
            if this.offset < this.read.len() {
                let n = out.remaining().min(this.read.len() - this.offset);
                out.put_slice(&this.read[this.offset..this.offset + n]);
                this.offset += n;
                if this.offset == this.read.len() {
                    this.read.clear();
                    this.offset = 0;
                }
                return Poll::Ready(Ok(()));
            }
            if this.read_closed {
                return Poll::Ready(Ok(()));
            }
            match ready!(Pin::new(&mut this.ws).poll_next(cx)) {
                Some(Ok(Message::Binary(bytes))) if bytes.is_empty() => {
                    // Empty binary marks a directional FIN. The opposite
                    // direction remains writable until its own FIN.
                    this.read_closed = true;
                    return Poll::Ready(Ok(()));
                }
                Some(Ok(Message::Binary(bytes))) if bytes.len() <= MAX_READ => {
                    this.read = bytes;
                }
                Some(Ok(Message::Binary(_))) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "invalid secure websocket frame",
                    )))
                }
                Some(Ok(Message::Ping(_))) | Some(Ok(Message::Pong(_))) => {
                    ready!(Pin::new(&mut this.ws).poll_flush(cx)).map_err(ws_error)?;
                    cx.waker().wake_by_ref();
                    return Poll::Pending;
                }
                Some(Ok(Message::Close(_))) | None => {
                    this.read_closed = true;
                    return Poll::Ready(Ok(()));
                }
                Some(Ok(_)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "nonbinary secure websocket frame",
                    )))
                }
                Some(Err(error)) => return Poll::Ready(Err(ws_error(error))),
            }
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for WsIo<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.write_closed {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        if bytes.is_empty() {
            return Poll::Ready(Ok(0));
        }
        ready!(Pin::new(&mut this.ws).poll_ready(cx)).map_err(ws_error)?;
        let n = bytes.len().min(MAX_WRITE);
        Pin::new(&mut this.ws)
            .start_send(Message::Binary(bytes[..n].to_vec()))
            .map_err(ws_error)?;
        Poll::Ready(Ok(n))
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        ready!(Pin::new(&mut self.get_mut().ws).poll_flush(cx)).map_err(ws_error)?;
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if !this.write_closed {
            ready!(Pin::new(&mut this.ws).poll_ready(cx)).map_err(ws_error)?;
            Pin::new(&mut this.ws)
                .start_send(Message::Binary(Vec::new()))
                .map_err(ws_error)?;
            this.write_closed = true;
        }
        ready!(Pin::new(&mut this.ws).poll_flush(cx)).map_err(ws_error)?;
        if !this.wire_closed {
            // The WS FIN is directional. Complete the underlying H2 send
            // half too: dropping an open RecvStream after the peer finishes
            // otherwise emits RST_STREAM(CANCEL) before reverse data drains.
            ready!(Pin::new(this.ws.get_mut()).poll_shutdown(cx))?;
            this.wire_closed = true;
        }
        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::{SinkExt, StreamExt};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio_tungstenite::tungstenite::protocol::Role;

    #[tokio::test]
    async fn binary_frames_preserve_inner_tls_bytes_and_refuse_text() {
        let (client, server) = tokio::io::duplex(64 * 1024);
        let client = WebSocketStream::from_raw_socket(client, Role::Client, None).await;
        let mut server = WebSocketStream::from_raw_socket(server, Role::Server, None).await;
        let mut carrier = WsIo::new(client);
        carrier.write_all(b"inner-tls-record").await.unwrap();
        carrier.flush().await.unwrap();
        let first = server.next().await.unwrap().unwrap().into_data();
        assert_eq!(first.as_slice(), b"inner-tls-record");
        server
            .send(Message::Binary(b"response".to_vec()))
            .await
            .unwrap();
        let mut received = [0u8; 8];
        carrier.read_exact(&mut received).await.unwrap();
        assert_eq!(&received, b"response");
        server
            .send(Message::Text("legacy-token".into()))
            .await
            .unwrap();
        assert_eq!(
            carrier.read_u8().await.unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[tokio::test]
    async fn directional_fin_keeps_reverse_response_writable() {
        let (client, server) = tokio::io::duplex(64 * 1024);
        let mut client =
            WsIo::new(WebSocketStream::from_raw_socket(client, Role::Client, None).await);
        let mut server =
            WsIo::new(WebSocketStream::from_raw_socket(server, Role::Server, None).await);
        client.write_all(b"request").await.unwrap();
        client.shutdown().await.unwrap();
        let mut request = Vec::new();
        server.read_to_end(&mut request).await.unwrap();
        assert_eq!(request.as_slice(), b"request");
        server.write_all(b"response").await.unwrap();
        server.shutdown().await.unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).await.unwrap();
        assert_eq!(response.as_slice(), b"response");
        assert_eq!(
            client.write_all(b"replay").await.unwrap_err().kind(),
            io::ErrorKind::BrokenPipe
        );
    }
}
