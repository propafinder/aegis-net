//! Geneva-style evolvable packet-manipulation strategies.
//!
//! A *strategy* is a small program — triggers matched against packet header
//! fields, each firing a tree of packet actions (duplicate, fragment, tamper,
//! drop). Rather than hand-writing evasions for one censor, strategies are
//! **evolved** against a model of it, which is what makes the approach
//! interesting: it finds evasions nobody thought to write.
//!
//! The library engine/trainer is offline: strategies are values and execution
//! operates on packet models or explicit wire images. The optional `live-linux`
//! feature also builds a separate, bounded AF_PACKET bridge executable; it is
//! opt-in and does not replace the client/full-wide interception path.
//!
//! Module map, split small on purpose:
//! - [`packet`]   — the packet model and `PROTO:field` addressing.
//! - [`syntax`]   — the strategy DSL: triggers, action trees, parser, printer.
//! - [`actions`]  — what each primitive does to a packet.
//! - [`engine`]   — applying a strategy to a packet stream.
//! - [`censor`]   — censor models to evolve against.
//! - [`evolve`]   — the genetic algorithm.

pub mod actions;
pub mod censor;
pub mod engine;
pub mod error;
pub mod evolve;
pub mod packet;
pub mod syntax;

pub use error::{Error, Result};
pub use syntax::strategy::Strategy;

pub mod live;
