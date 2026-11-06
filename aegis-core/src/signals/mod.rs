//! Сигналы обратной связи: классификация результатов соединений и метрики.

pub mod classify;
pub mod metrics;

pub use classify::{classify_outcome, FailSignal, OutcomeContext};
pub use metrics::{ObservedEvent, RuntimeMetrics};
