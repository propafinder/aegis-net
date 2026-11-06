use thiserror::Error;

pub type Result<T> = std::result::Result<T, AegisError>;

#[derive(Debug, Error)]
pub enum AegisError {
    #[error("IO: {0}")]
    Io(#[from] std::io::Error),
    #[error("protocol: {0}")]
    Protocol(String),
    #[error("TLS parse: {0}")]
    TlsParse(String),
    #[error("relay codec: {0}")]
    RelayCodec(String),
    #[error("auth failed")]
    Auth,
    #[error("invalid config: {0}")]
    Config(String),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
}
