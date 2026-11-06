//! Real ICE/DTLS/SCTP carrier for an existing inner TLS device channel.
//!
//! Owned signaling admission is an additional gate, never device authentication.
//! This crate does not implement Tor Snowflake or media/codec substitution.

mod endpoint;
mod policy;
pub mod runtime_settings;
#[cfg(feature = "sfu-media-vp8")]
pub mod sfu_livekit;
pub mod sfu_media;
#[cfg(feature = "sfu-media-vp8")]
pub mod sfu_peer;
#[cfg(feature = "sfu-media-vp8")]
pub mod sfu_vp8;
mod signaling;
mod stream;

pub use endpoint::{accept, connect, Cancellation, CarrierConfig};
pub use policy::{IcePolicy, PathEvidence, TurnServer};
pub use signaling::{
    AdmissionKey, BrokerLimits, MediaGrantIssuer, Operation, OwnedBroker, Role, SessionId, Signal,
    Signaling, SignalingReply, SignalingRequest, TlsSignalingClient,
};
pub use stream::WebRtcStream;

/// Errors intentionally omit SDP, ICE addresses, credentials and upstream text.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("WebRTC configuration rejected")]
    Configuration,
    #[error("signaling admission refused")]
    Admission,
    #[error("signaling capacity exhausted")]
    Capacity,
    #[error("signaling session unavailable")]
    Session,
    #[error("WebRTC deadline exceeded")]
    Deadline,
    #[error("WebRTC operation cancelled")]
    Cancelled,
    #[error("WebRTC carrier negotiation failed")]
    Negotiation,
    #[error("WebRTC data channel contract rejected")]
    Channel,
    #[error("WebRTC selected path rejected")]
    Path,
    #[error("bounded signaling protocol rejected")]
    Signaling,
    #[error("SFU media session adapter is not implemented")]
    UnsupportedSfu,
}

pub type Result<T> = std::result::Result<T, Error>;

#[cfg(test)]
mod tests;
