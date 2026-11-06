//! Shared actual dual-stack packet engine. Native capture and credential
//! admission remain with the independently owned caller; no provider factory.
pub mod dns;
pub mod engine;
#[path = "../ingress/wide/linux_nfqueue.rs"]
pub mod linux_nfqueue;
pub mod services;
#[path = "../ingress/wide/tcp_stream_pump.rs"]
mod tcp_stream_pump;
pub use engine::run_ready_with_services;
