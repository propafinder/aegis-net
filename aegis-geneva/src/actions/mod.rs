//! What each Geneva primitive does to a packet.
//!
//! Each primitive is its own module and its own pure function, so it can be
//! tested — and reasoned about — on its own. `drop` has no module: discarding
//! a packet is the absence of an action, handled by the engine.

pub mod duplicate;
pub mod fragment;
pub mod payload;
pub mod tamper;
