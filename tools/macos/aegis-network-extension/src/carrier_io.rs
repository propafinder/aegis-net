//! One owned byte stream under the inner enrolled TLS session.
//!
//! The outer route owns its connection driver and any pump for as long as
//! this stream is retained. Admission of a new route requires a concrete
//! constructor that returns this type together with its terminal owner;
//! boxing an H2 stream here does not admit another wire protocol.
use tokio::io::{AsyncRead, AsyncWrite};

pub(crate) trait CarrierIo: AsyncRead + AsyncWrite + Unpin + Send {}

impl<T> CarrierIo for T where T: AsyncRead + AsyncWrite + Unpin + Send {}

pub(crate) type OwnedCarrier = Box<dyn CarrierIo>;
pub(crate) type InnerCarrier = tokio_rustls::client::TlsStream<OwnedCarrier>;

pub(crate) fn own<T>(stream: T) -> OwnedCarrier
where
    T: CarrierIo + 'static,
{
    Box::new(stream)
}
