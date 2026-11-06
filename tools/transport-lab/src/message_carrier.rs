//! Ordered message-to-byte-stream contract for local research fixtures.
//!
//! This is **not** WebRTC, ICE, Snowflake, Protozoa or an SFU transport. It
//! models a reliable ordered message service so the existing Aegis inner
//! secure channel can use its normal `AsyncRead + AsyncWrite` interface.
//! The carrier adds no encryption or device authentication of its own.

use serde::{Deserialize, Serialize};
use std::{
    future::Future,
    io,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::mpsc::{self, error::SendError, OwnedPermit, Receiver, Sender},
};

/// Maximum payload per message, independent of the caller's write size.
pub const MAX_FRAGMENT_BYTES: usize = 8 * 1024;
/// Upper bound on the number of queued messages in each direction.
pub const MAX_QUEUE_MESSAGES: usize = 256;

/// An ordered frame, starting at sequence zero independently per direction.
///
/// External codecs must enforce a byte limit **before** deserializing this
/// envelope. A bounded channel limits message count, not arbitrary allocations
/// made by its producer or a JSON decoder. Valid data is nonempty and at most
/// `MAX_FRAGMENT_BYTES`; FIN carries the next sequence and ends that direction.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum MessageFrame {
    Data { sequence: u64, payload: Vec<u8> },
    Fin { sequence: u64 },
}

// Payloads may contain TLS records or application data; never print them.
impl std::fmt::Debug for MessageFrame {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Data { sequence, payload } => f
                .debug_struct("Data")
                .field("sequence", sequence)
                .field("payload_bytes", &payload.len())
                .finish(),
            Self::Fin { sequence } => f.debug_struct("Fin").field("sequence", sequence).finish(),
        }
    }
}

type Reservation =
    Pin<Box<dyn Future<Output = Result<OwnedPermit<MessageFrame>, SendError<()>>> + Send>>;

/// Finite, backpressured adapter. No bytes are copied while a write is pending.
///
/// A local pair retains at most `queue_capacity * MAX_FRAGMENT_BYTES` of valid
/// queued payload per direction, plus one partial read fragment per endpoint.
/// `flush` confirms local enqueueing only, not remote receipt or delivery.
pub struct MessageCarrier {
    tx: Sender<MessageFrame>,
    rx: Receiver<MessageFrame>,
    reservation: Option<Reservation>,
    write_sequence: u64,
    read_sequence: u64,
    partial_read: Vec<u8>,
    read_offset: usize,
    read_fin_received: bool,
    read_finished: bool,
    write_finished: bool,
    read_failure: Option<(io::ErrorKind, &'static str)>,
    write_failed: bool,
}

impl MessageCarrier {
    /// Create a local, bidirectional pair with finite message queues.
    pub fn pair(queue_capacity: usize) -> io::Result<(Self, Self)> {
        if !(1..=MAX_QUEUE_MESSAGES).contains(&queue_capacity) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "message queue capacity outside supported bounds",
            ));
        }
        let (a_tx, b_rx) = mpsc::channel(queue_capacity);
        let (b_tx, a_rx) = mpsc::channel(queue_capacity);
        Ok((
            Self::from_channels(a_tx, a_rx)?,
            Self::from_channels(b_tx, b_rx)?,
        ))
    }

    /// Adapt channels supplied by a bounded ordered-message fixture.
    ///
    /// Producers must bound their own decoding allocations as described on
    /// `MessageFrame`. Frames are checked before being retained for byte reads.
    pub fn from_channels(tx: Sender<MessageFrame>, rx: Receiver<MessageFrame>) -> io::Result<Self> {
        if tx.max_capacity() > MAX_QUEUE_MESSAGES || rx.max_capacity() > MAX_QUEUE_MESSAGES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "message queue exceeds supported bounds",
            ));
        }
        Ok(Self {
            tx,
            rx,
            reservation: None,
            write_sequence: 0,
            read_sequence: 0,
            partial_read: Vec::new(),
            read_offset: 0,
            read_fin_received: false,
            read_finished: false,
            write_finished: false,
            read_failure: None,
            write_failed: false,
        })
    }

    fn read_error(&mut self, kind: io::ErrorKind, message: &'static str) -> io::Error {
        self.read_failure = Some((kind, message));
        self.write_failed = true;
        self.reservation = None;
        self.partial_read.clear();
        self.rx.close();
        io::Error::new(kind, message)
    }

    fn broken_pipe() -> io::Error {
        io::Error::new(
            io::ErrorKind::BrokenPipe,
            "message carrier write direction closed",
        )
    }

    fn poll_read_end(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // A producer may hold a permit acquired before close(). Wait until
        // those permits are released; accepting EOF earlier would hide a
        // subsequently committed trailing frame.
        match self.rx.poll_recv(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Some(_)) => Poll::Ready(Err(self.read_error(
                io::ErrorKind::InvalidData,
                "message carrier frame after FIN",
            ))),
            Poll::Ready(None) => {
                self.read_finished = true;
                Poll::Ready(Ok(()))
            }
        }
    }

    fn poll_permit(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<OwnedPermit<MessageFrame>>> {
        if self.reservation.is_none() {
            self.reservation = Some(Box::pin(self.tx.clone().reserve_owned()));
        }
        let result = self
            .reservation
            .as_mut()
            .expect("reservation initialized")
            .as_mut()
            .poll(cx);
        match result {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(permit)) => {
                self.reservation = None;
                Poll::Ready(Ok(permit))
            }
            Poll::Ready(Err(_)) => {
                self.reservation = None;
                self.write_failed = true;
                Poll::Ready(Err(Self::broken_pipe()))
            }
        }
    }
}

impl AsyncRead for MessageCarrier {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if let Some((kind, message)) = this.read_failure {
            return Poll::Ready(Err(io::Error::new(kind, message)));
        }
        if out.remaining() == 0 || this.read_finished {
            return Poll::Ready(Ok(()));
        }
        if this.read_fin_received {
            return this.poll_read_end(cx);
        }
        if this.read_offset == this.partial_read.len() {
            this.partial_read.clear();
            this.read_offset = 0;
            match this.rx.poll_recv(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(None) => {
                    return Poll::Ready(Err(this.read_error(
                        io::ErrorKind::UnexpectedEof,
                        "message carrier ended without FIN",
                    )))
                }
                Poll::Ready(Some(MessageFrame::Data { sequence, payload })) => {
                    if sequence != this.read_sequence {
                        return Poll::Ready(Err(this.read_error(
                            io::ErrorKind::InvalidData,
                            "message carrier sequence mismatch",
                        )));
                    }
                    if payload.is_empty() || payload.len() > MAX_FRAGMENT_BYTES {
                        return Poll::Ready(Err(this.read_error(
                            io::ErrorKind::InvalidData,
                            "message carrier invalid fragment size",
                        )));
                    }
                    let Some(next) = this.read_sequence.checked_add(1) else {
                        return Poll::Ready(Err(this.read_error(
                            io::ErrorKind::InvalidData,
                            "message carrier sequence exhausted",
                        )));
                    };
                    this.read_sequence = next;
                    this.partial_read = payload;
                }
                Poll::Ready(Some(MessageFrame::Fin { sequence })) => {
                    if sequence != this.read_sequence {
                        return Poll::Ready(Err(this.read_error(
                            io::ErrorKind::InvalidData,
                            "message carrier FIN sequence mismatch",
                        )));
                    }
                    // Stop new permits and drain preexisting permits/frames.
                    this.rx.close();
                    this.read_fin_received = true;
                    return this.poll_read_end(cx);
                }
            }
        }
        let count = out
            .remaining()
            .min(this.partial_read.len() - this.read_offset);
        out.put_slice(&this.partial_read[this.read_offset..this.read_offset + count]);
        this.read_offset += count;
        if this.read_offset == this.partial_read.len() {
            this.partial_read.clear();
            this.read_offset = 0;
        }
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for MessageCarrier {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.write_finished || this.write_failed {
            return Poll::Ready(Err(Self::broken_pipe()));
        }
        if bytes.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let Some(next) = this.write_sequence.checked_add(1) else {
            this.write_failed = true;
            this.reservation = None;
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "message carrier sequence exhausted",
            )));
        };
        let permit = match this.poll_permit(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Ready(Ok(permit)) => permit,
        };
        let count = bytes.len().min(MAX_FRAGMENT_BYTES);
        permit.send(MessageFrame::Data {
            sequence: this.write_sequence,
            payload: bytes[..count].to_vec(),
        });
        this.write_sequence = next;
        Poll::Ready(Ok(count))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        // A cancelled poll_write retained only a reservation, never payload.
        this.reservation = None;
        if this.write_failed {
            Poll::Ready(Err(Self::broken_pipe()))
        } else {
            Poll::Ready(Ok(()))
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.write_failed {
            return Poll::Ready(Err(Self::broken_pipe()));
        }
        if this.write_finished {
            return Poll::Ready(Ok(()));
        }
        let permit = match this.poll_permit(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Ready(Ok(permit)) => permit,
        };
        permit.send(MessageFrame::Fin {
            sequence: this.write_sequence,
        });
        this.write_finished = true;
        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::future::poll_fn;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn fragments_and_partial_reads_preserve_full_payload() {
        let payload: Vec<u8> = (0..MAX_FRAGMENT_BYTES * 3 + 17)
            .map(|i| (i % 251) as u8)
            .collect();
        let expected = payload.clone();
        let (mut writer, mut reader) = MessageCarrier::pair(2).unwrap();
        let send = tokio::spawn(async move {
            writer.write_all(&payload).await.unwrap();
            writer.shutdown().await.unwrap();
        });
        let mut actual = Vec::new();
        let mut tiny = [0u8; 37];
        loop {
            let count = reader.read(&mut tiny).await.unwrap();
            if count == 0 {
                break;
            }
            actual.extend_from_slice(&tiny[..count]);
        }
        send.await.unwrap();
        assert_eq!(actual, expected);
    }

    #[tokio::test]
    async fn finite_queue_applies_backpressure_until_reader_progresses() {
        let (mut writer, mut reader) = MessageCarrier::pair(1).unwrap();
        assert_eq!(
            writer
                .write(&vec![7; MAX_FRAGMENT_BYTES + 1])
                .await
                .unwrap(),
            MAX_FRAGMENT_BYTES
        );
        poll_fn(|cx| {
            assert!(Pin::new(&mut writer).poll_write(cx, &[8]).is_pending());
            Poll::Ready(())
        })
        .await;
        let mut payload = vec![0; MAX_FRAGMENT_BYTES];
        reader.read_exact(&mut payload).await.unwrap();
        assert!(payload.iter().all(|byte| *byte == 7));
        assert_eq!(writer.write(&[8]).await.unwrap(), 1);
        assert_eq!(reader.read_u8().await.unwrap(), 8);
        writer.shutdown().await.unwrap();
        assert_eq!(reader.read(&mut [0]).await.unwrap(), 0);
    }

    fn raw_receiver() -> (Sender<MessageFrame>, MessageCarrier) {
        let (incoming, rx) = mpsc::channel(4);
        let (tx, _unused) = mpsc::channel(4);
        (incoming, MessageCarrier::from_channels(tx, rx).unwrap())
    }

    #[tokio::test]
    async fn gap_duplicate_and_reordering_fail_permanently() {
        for sequences in [vec![1], vec![0, 0], vec![0, 2, 1]] {
            let (incoming, mut reader) = raw_receiver();
            for sequence in sequences {
                incoming
                    .send(MessageFrame::Data {
                        sequence,
                        payload: vec![9],
                    })
                    .await
                    .unwrap();
            }
            let mut actual = Vec::new();
            assert_eq!(
                reader.read_to_end(&mut actual).await.unwrap_err().kind(),
                io::ErrorKind::InvalidData
            );
            assert_eq!(
                reader.read(&mut [0]).await.unwrap_err().kind(),
                io::ErrorKind::InvalidData
            );
            assert_eq!(
                reader.write(b"must not continue").await.unwrap_err().kind(),
                io::ErrorKind::BrokenPipe
            );
        }
    }

    #[tokio::test]
    async fn malformed_sizes_and_missing_fin_are_rejected() {
        for payload in [Vec::new(), vec![0; MAX_FRAGMENT_BYTES + 1]] {
            let (incoming, mut reader) = raw_receiver();
            incoming
                .send(MessageFrame::Data {
                    sequence: 0,
                    payload,
                })
                .await
                .unwrap();
            assert_eq!(
                reader.read(&mut [0]).await.unwrap_err().kind(),
                io::ErrorKind::InvalidData
            );
        }
        let (incoming, mut reader) = raw_receiver();
        incoming
            .send(MessageFrame::Data {
                sequence: 0,
                payload: vec![1],
            })
            .await
            .unwrap();
        drop(incoming);
        assert_eq!(reader.read_u8().await.unwrap(), 1);
        assert_eq!(
            reader.read(&mut [0]).await.unwrap_err().kind(),
            io::ErrorKind::UnexpectedEof
        );
        assert!(MessageCarrier::pair(0).is_err());
        assert!(MessageCarrier::pair(MAX_QUEUE_MESSAGES + 1).is_err());
    }

    #[tokio::test]
    async fn fin_is_directional_and_trailing_frames_are_rejected() {
        let (mut a, mut b) = MessageCarrier::pair(2).unwrap();
        a.write_all(b"abc").await.unwrap();
        a.shutdown().await.unwrap();
        a.shutdown().await.unwrap();
        assert_eq!(
            a.write(b"extra").await.unwrap_err().kind(),
            io::ErrorKind::BrokenPipe
        );
        let mut received = Vec::new();
        b.read_to_end(&mut received).await.unwrap();
        assert_eq!(received, b"abc");
        b.write_all(b"ack").await.unwrap();
        b.shutdown().await.unwrap();
        received.clear();
        a.read_to_end(&mut received).await.unwrap();
        assert_eq!(received, b"ack");
        let (incoming, mut reader) = raw_receiver();
        incoming
            .send(MessageFrame::Fin { sequence: 0 })
            .await
            .unwrap();
        incoming
            .send(MessageFrame::Data {
                sequence: 1,
                payload: vec![0],
            })
            .await
            .unwrap();
        assert_eq!(
            reader.read(&mut [0]).await.unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        let (incoming, mut reader) = raw_receiver();
        let outstanding = incoming.clone().reserve_owned().await.unwrap();
        incoming
            .send(MessageFrame::Fin { sequence: 0 })
            .await
            .unwrap();
        poll_fn(|cx| {
            let mut storage = [0];
            let mut output = ReadBuf::new(&mut storage);
            assert!(Pin::new(&mut reader)
                .poll_read(cx, &mut output)
                .is_pending());
            Poll::Ready(())
        })
        .await;
        outstanding.send(MessageFrame::Data {
            sequence: 1,
            payload: vec![0],
        });
        assert_eq!(
            reader.read(&mut [0]).await.unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[tokio::test]
    async fn cancelled_pending_write_never_enqueues_its_bytes() {
        let (mut writer, mut reader) = MessageCarrier::pair(1).unwrap();
        writer.write_all(b"a").await.unwrap();
        poll_fn(|cx| {
            assert!(Pin::new(&mut writer)
                .poll_write(cx, b"cancelled")
                .is_pending());
            Poll::Ready(())
        })
        .await;
        assert_eq!(reader.read_u8().await.unwrap(), b'a');
        writer.write_all(b"c").await.unwrap();
        assert_eq!(reader.read_u8().await.unwrap(), b'c');
        writer.shutdown().await.unwrap();
        assert_eq!(reader.read(&mut [0]).await.unwrap(), 0);
        let (mut writer, reader) = MessageCarrier::pair(1).unwrap();
        drop(reader);
        assert_eq!(
            writer.write(b"x").await.unwrap_err().kind(),
            io::ErrorKind::BrokenPipe
        );
    }
}
