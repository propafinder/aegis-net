//! State v2: расширенная схема + async batch persistence.
//!
//! Сосуществует с `state.rs` (v1) до полной миграции Brain в M5.
//! Сейчас `state_v2` уже является основным runtime store, а `state.rs` сохраняется
//! как legacy-формат для совместимости и миграции старых state-файлов.

mod bounds;
pub mod persist;
pub mod schema;

pub use persist::AsyncStateStore;
pub use schema::{
    HybridRouteStats, KeyObservation, ObservationContract, ObservedWireChoreographyHint,
    ObservedWireIpv4HeaderShaping, ObservedWireNegotiatedOptions, StallProbeStats, StateSnapshot,
    StrategyStatsV2, TransportStats,
};
