//! Стратегии отправки первого буфера (Direct Mode).

mod checksum_trick;
mod fake_disorder;
mod fake_rst;
mod geneva;
mod ip_frag;
mod multisplit;
mod oob;
mod overlap;
mod passthrough;
mod ttl_desync;
mod ttl_pattern;
mod ttl_sets;

pub use ttl_sets::{pick_low_decoy_ttl, pick_normal_ttl, LOW_DECOY_TTL_SET, NORMAL_TTL_SET};

pub use checksum_trick::ChecksumTrickStrategy;
pub use fake_disorder::FakeDisorderStrategy;
pub use fake_rst::FakeRstStrategy;
pub use geneva::{
    configure as configure_geneva, configured_strategy as geneva_configured_strategy,
    GenevaStrategy,
};
pub use ip_frag::IpFragStrategy;
pub use multisplit::MultisplitStrategy;
pub use oob::OobDataStrategy;
pub use overlap::OverlapStrategy;
pub use passthrough::PassthroughStrategy;
pub use ttl_desync::TtlDesyncStrategy;
pub use ttl_pattern::TtlPatternStrategy;

use crate::raw_engine::RawCapabilities;
use crate::DirectTerminalReason;
use async_trait::async_trait;
use std::net::SocketAddr;
use tokio::net::TcpStream;

/// Контекст первой отправки (Direct): адрес цели для raw/decoy путей.
#[derive(Clone, Copy, Debug)]
pub struct SendFirstContext {
    pub dst: SocketAddr,
    /// Observed hop distance to the destination. Geneva uses this to prove a
    /// payload-altered decoy expires before the real server.
    pub reference_path_hops: Option<u8>,
}

/// Capability requirements used by the direct planner before opening a TCP attempt.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct StrategyRequirements {
    pub needs_raw_ipv4: bool,
    pub needs_exact_tcp_seq: bool,
    pub ipv4_only: bool,
}

impl StrategyRequirements {
    pub fn unsatisfied_reason(
        &self,
        dst: SocketAddr,
        raw: RawCapabilities,
    ) -> Option<DirectTerminalReason> {
        if self.ipv4_only && !dst.is_ipv4() {
            return Some(DirectTerminalReason::UnsupportedAddressFamily);
        }
        if (self.needs_raw_ipv4 && !raw.ipv4_raw_send)
            || (self.needs_exact_tcp_seq && !raw.tcp_repair_query)
        {
            return Some(DirectTerminalReason::MissingRawCapability);
        }
        None
    }

    pub fn is_satisfied(&self, dst: SocketAddr, raw: RawCapabilities) -> bool {
        self.unsatisfied_reason(dst, raw).is_none()
    }
}

#[async_trait]
pub trait Strategy: Send + Sync {
    fn id(&self) -> &'static str;

    fn requirements(&self) -> StrategyRequirements {
        StrategyRequirements::default()
    }

    /// Validate every strategy-specific prerequisite that can be checked
    /// without writing a decoy or the canonical application payload. An error
    /// from this hook is therefore replay-safe. `send_first` errors remain
    /// conservatively ambiguous because a strategy may already have emitted
    /// application bytes before returning them.
    fn preflight_send_first(
        &self,
        _data: &[u8],
        _sni: Option<(usize, usize)>,
        _ctx: &SendFirstContext,
    ) -> std::io::Result<()> {
        Ok(())
    }

    /// Отправить первый чанк на уже подключённый TCP к цели.
    async fn send_first(
        &self,
        stream: &mut TcpStream,
        data: &[u8],
        sni: Option<(usize, usize)>,
        ctx: &SendFirstContext,
    ) -> std::io::Result<()>;
}
