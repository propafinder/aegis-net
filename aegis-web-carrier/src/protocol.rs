use crate::{convert, rejected};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::{future::poll_fn, io};

pub const OPEN: u8 = 1;
pub const FIN: u8 = 2;
pub const CANCEL: u8 = 4;
pub const HEADER: usize = 53;
pub const RESPONSE_HEADER: usize = 45;
const MAGIC: &[u8; 4] = b"AWR1";

pub struct Frame {
    pub id: [u8; 32],
    pub sequence: u64,
    pub ack: u64,
    pub flags: u8,
    pub data: Bytes,
}
impl Frame {
    pub fn encode(&self) -> Bytes {
        let mut bytes = BytesMut::with_capacity(HEADER + self.data.len());
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&self.id);
        bytes.put_u64(self.sequence);
        bytes.put_u64(self.ack);
        bytes.put_u8(self.flags);
        bytes.extend_from_slice(&self.data);
        bytes.freeze()
    }
    pub fn decode(mut body: Bytes, max: usize) -> io::Result<Self> {
        if body.len() < HEADER || body.len() > HEADER + max || &body[..4] != MAGIC {
            return Err(rejected());
        }
        body.advance(4);
        let mut id = [0; 32];
        body.copy_to_slice(&mut id);
        let sequence = body.get_u64();
        let ack = body.get_u64();
        let flags = body.get_u8();
        if flags & !(OPEN | FIN | CANCEL) != 0 || id == [0; 32] {
            return Err(rejected());
        }
        Ok(Self {
            id,
            sequence,
            ack,
            flags,
            data: body,
        })
    }
}
pub struct Reply {
    pub id: [u8; 32],
    pub sequence: u64,
    pub fin: bool,
    pub data: Bytes,
}
impl Reply {
    pub fn encode(&self) -> Bytes {
        let mut body = BytesMut::with_capacity(RESPONSE_HEADER + self.data.len());
        body.extend_from_slice(MAGIC);
        body.extend_from_slice(&self.id);
        body.put_u64(self.sequence);
        body.put_u8(u8::from(self.fin));
        body.extend_from_slice(&self.data);
        body.freeze()
    }
    pub fn decode(mut body: Bytes, max: usize) -> io::Result<Self> {
        if body.len() < RESPONSE_HEADER || body.len() > RESPONSE_HEADER + max || &body[..4] != MAGIC
        {
            return Err(rejected());
        }
        body.advance(4);
        let mut id = [0; 32];
        body.copy_to_slice(&mut id);
        let sequence = body.get_u64();
        let flags = body.get_u8();
        if flags > 1 {
            return Err(rejected());
        }
        Ok(Self {
            id,
            sequence,
            fin: flags == 1,
            data: body,
        })
    }
}
pub async fn collect(mut receive: h2::RecvStream, max: usize) -> io::Result<Bytes> {
    let mut body = BytesMut::new();
    while let Some(chunk) = receive.data().await {
        let chunk = chunk.map_err(convert)?;
        if body.len().saturating_add(chunk.len()) > max {
            return Err(rejected());
        }
        receive
            .flow_control()
            .release_capacity(chunk.len())
            .map_err(convert)?;
        body.extend_from_slice(&chunk);
    }
    if receive.trailers().await.map_err(convert)?.is_some() {
        return Err(rejected());
    }
    Ok(body.freeze())
}
pub async fn send(mut stream: h2::SendStream<Bytes>, mut body: Bytes) -> io::Result<()> {
    if body.is_empty() {
        stream.send_data(body, true).map_err(convert)?;
        return Ok(());
    }
    while !body.is_empty() {
        stream.reserve_capacity(body.len());
        let capacity = poll_fn(|cx| stream.poll_capacity(cx))
            .await
            .ok_or_else(crate::failed)?
            .map_err(convert)?;
        if capacity == 0 {
            continue;
        }
        let count = capacity.min(body.len());
        let chunk = body.split_to(count);
        stream.send_data(chunk, body.is_empty()).map_err(convert)?;
    }
    Ok(())
}
