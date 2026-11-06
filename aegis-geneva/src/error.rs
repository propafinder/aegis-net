//! Errors from parsing and applying strategies.

use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum Error {
    #[error("strategy syntax: {0}")]
    Syntax(String),
    #[error("unknown field {proto}:{field}")]
    UnknownField { proto: String, field: String },
    #[error("field {0} does not accept value {1}")]
    BadFieldValue(String, String),
    #[error("action tree exceeds the maximum depth of {0}")]
    TooDeep(usize),
}

pub type Result<T> = std::result::Result<T, Error>;
