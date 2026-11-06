//! The genetic trainer.
//!
//! - [`random`]    — generating raw material.
//! - [`fitness`]   — scoring a strategy against a censor model.
//! - [`mutate`]    — small random changes.
//! - [`crossover`] — recombining two strategies.
//! - [`ga`]        — the generational loop tying them together.

pub mod crossover;
pub mod fitness;
pub mod ga;
pub mod mutate;
pub mod random;
