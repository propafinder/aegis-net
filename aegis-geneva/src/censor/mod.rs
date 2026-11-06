//! Censor models to evolve against.
//!
//! These are *models*, and the crate says so plainly: beating `PathCensor` is
//! evidence a strategy is worth testing for real, not evidence it works in
//! Russia. The value is that a model is cheap, deterministic, and can be made
//! stricter than the real thing.
//!
//! - [`model`]      — the `Censor` trait and its outcome type.
//! - [`inspection`] — how a censor looks: reassembly, checksums, RST handling.
//! - [`path`]       — a censor placed on the path by hop distance (TTL games).

pub mod inspection;
pub mod model;
pub mod path;

pub use model::{Censor, Outcome};
pub use path::PathCensor;
