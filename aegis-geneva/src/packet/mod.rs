//! The packet model and its field addressing.
//!
//! - [`field`] — `PROTO:field` addressing shared by triggers and tamper actions.
//! - [`model`] — the packet itself, plus TCP flag helpers.

pub mod field;
pub mod model;
