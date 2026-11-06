//! Datagram boundaries carried inside the authenticated TLS stream. There is
//! no independent cipher, nonce, replay window or unauthenticated clear header.
use std::io;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const MAX_PAYLOAD: usize = 65_507;

pub async fn write<S: AsyncWrite + Unpin>(stream: &mut S, payload: &[u8]) -> io::Result<()> {
    if payload.len() > MAX_PAYLOAD {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "secure datagram too large",
        ));
    }
    stream.write_u16(payload.len() as u16).await?;
    stream.write_all(payload).await?;
    stream.flush().await
}

/// Cancel only when discarding the entire stream, not between datagrams: a
/// partially read frame cannot be restarted. Empty datagrams remain distinct
/// from a clean EOF before the next frame; truncated prefixes/payloads fail.
pub async fn read<S: AsyncRead + Unpin>(stream: &mut S) -> io::Result<Option<Vec<u8>>> {
    let first = match stream.read_u8().await {
        Ok(byte) => byte,
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    };
    let length = u16::from_be_bytes([first, stream.read_u8().await?]) as usize;
    if length > MAX_PAYLOAD {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "secure datagram too large",
        ));
    }
    let mut payload = vec![0; length];
    stream.read_exact(&mut payload).await?;
    Ok(Some(payload))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn preserves_fragmented_empty_and_multiple_datagram_boundaries() {
        let (mut tx, mut rx) = tokio::io::duplex(3);
        let sender = tokio::spawn(async move {
            write(&mut tx, b"").await.unwrap();
            write(&mut tx, b"first datagram").await.unwrap();
            write(&mut tx, b"second").await.unwrap();
            write(&mut tx, &vec![0x5c; 60_000]).await.unwrap();
        });
        assert_eq!(read(&mut rx).await.unwrap(), Some(vec![]));
        assert_eq!(
            read(&mut rx).await.unwrap().as_deref(),
            Some(b"first datagram".as_slice())
        );
        assert_eq!(
            read(&mut rx).await.unwrap().as_deref(),
            Some(b"second".as_slice())
        );
        assert_eq!(read(&mut rx).await.unwrap().unwrap(), vec![0x5c; 60_000]);
        assert!(read(&mut rx).await.unwrap().is_none());
        sender.await.unwrap();
    }

    #[tokio::test]
    async fn rejects_truncation_and_oversized_prefix_before_allocation() {
        for bytes in [&b"\x00"[..], &b"\x00\x03a"[..], &b"\xff\xff"[..]] {
            assert!(read(&mut &*bytes).await.is_err());
        }
        let mut sink = Vec::new();
        assert!(write(&mut sink, &vec![0; MAX_PAYLOAD + 1]).await.is_err());
        assert!(sink.is_empty());
    }
}
