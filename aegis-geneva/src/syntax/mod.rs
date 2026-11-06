//! The strategy language: triggers, action trees, and their text form.
//!
//! - [`trigger`]  — `[PROTO:field:value]`, the match half of a rule.
//! - [`action`]   — the action tree and its primitives.
//! - [`parse`]    — the DSL parser.
//! - [`strategy`] — rules and the two-half strategy that holds them.

pub mod action;
pub mod parse;
pub mod strategy;
pub mod trigger;
