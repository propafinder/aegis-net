//! Causal integer admission for alpha(t)=b+r*t. Rate-latency bounds remain
//! conditional on a genuine FIFO service curve; nominal cadence is no proof.
use serde::{Deserialize, Serialize};
use thiserror::Error;

const NS_PER_SECOND: u128 = 1_000_000_000;
pub const MAX_BURST_BYTES: u64 = 16 * 1024 * 1024;
pub const MAX_RATE_BYTES_PER_SECOND: u64 = 1024 * 1024 * 1024;
pub const MAX_LIFETIME_NS: u64 = 3600 * 1_000_000_000;
pub const MAX_ADMISSIONS: u64 = 1_000_000;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Settings {
    pub burst_bytes: u64,
    pub arrival_rate_bytes_per_second: u64,
    pub service_rate_bytes_per_second: u64,
    pub service_latency_ns: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum GuardError {
    #[error("network-calculus parameter or local ceiling outside bounds")]
    Parameters,
    #[error("network-calculus arithmetic overflow")]
    Overflow,
    #[error("nonmonotonic or expired network-calculus arrival clock")]
    Clock,
    #[error("empty or excessive network-calculus arrival")]
    Arrival,
    #[error("network-calculus arrival exceeds exact token balance")]
    BurstExceeded,
    #[error("network-calculus service premise explicitly invalidated")]
    ServiceInvalidated,
    #[error("network-calculus event/cumulative byte bound exhausted")]
    Capacity,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ConditionalBounds {
    pub backlog_bytes_ceiling: u64,
    pub fifo_delay_ns_ceiling: u64,
    pub guaranteed_service_verified: bool,
    pub requires_fifo_rate_latency_service: bool,
}
fn ceil_div(n: u128, d: u128) -> Result<u128, GuardError> {
    if d == 0 {
        return Err(GuardError::Parameters);
    }
    n.checked_add(d - 1)
        .map(|v| v / d)
        .ok_or(GuardError::Overflow)
}
impl Settings {
    pub fn validate(&self) -> Result<(), GuardError> {
        if !(1..=MAX_BURST_BYTES).contains(&self.burst_bytes)
            || self.arrival_rate_bytes_per_second > MAX_RATE_BYTES_PER_SECOND
            || !(1..=MAX_RATE_BYTES_PER_SECOND).contains(&self.service_rate_bytes_per_second)
            || self.service_rate_bytes_per_second < self.arrival_rate_bytes_per_second
            || self.service_latency_ns > MAX_LIFETIME_NS
        {
            return Err(GuardError::Parameters);
        }
        Ok(())
    }
    /// Necessary local upper-capacity check only. This cannot verify scheduler,
    /// socket, remote queue or network lower-service guarantees. T includes at
    /// least one whole discrete frame period; external slack remains required.
    pub fn validate_local_ceiling(
        &self,
        payload_bytes: u64,
        period_ns: u64,
    ) -> Result<(), GuardError> {
        self.validate()?;
        if payload_bytes == 0
            || payload_bytes > MAX_BURST_BYTES
            || period_ns == 0
            || period_ns > MAX_LIFETIME_NS
            || self.service_latency_ns < period_ns
        {
            return Err(GuardError::Parameters);
        }
        let ceiling = u128::from(payload_bytes)
            .checked_mul(NS_PER_SECOND)
            .ok_or(GuardError::Overflow)?
            / u128::from(period_ns);
        if u128::from(self.service_rate_bytes_per_second) > ceiling {
            return Err(GuardError::Parameters);
        }
        Ok(())
    }
    pub fn theoretical_bounds(&self) -> Result<ConditionalBounds, GuardError> {
        self.validate()?;
        let burst = u128::from(self.burst_bytes)
            .checked_mul(NS_PER_SECOND)
            .ok_or(GuardError::Overflow)?;
        let rate_latency = u128::from(self.arrival_rate_bytes_per_second)
            .checked_mul(u128::from(self.service_latency_ns))
            .ok_or(GuardError::Overflow)?;
        let backlog = ceil_div(
            burst
                .checked_add(rate_latency)
                .ok_or(GuardError::Overflow)?,
            NS_PER_SECOND,
        )?;
        let delay = u128::from(self.service_latency_ns)
            .checked_add(ceil_div(
                burst,
                u128::from(self.service_rate_bytes_per_second),
            )?)
            .ok_or(GuardError::Overflow)?;
        Ok(ConditionalBounds {
            backlog_bytes_ceiling: backlog.try_into().map_err(|_| GuardError::Overflow)?,
            fifo_delay_ns_ceiling: delay.try_into().map_err(|_| GuardError::Overflow)?,
            guaranteed_service_verified: false,
            requires_fifo_rate_latency_service: true,
        })
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Admission {
    pub admitted_bytes: u64,
    pub cumulative_admitted_bytes: u64,
    pub admission_count: u64,
    pub elapsed_ns: u64,
    pub arrival_envelope_enforced: bool,
    pub guaranteed_service_verified: bool,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Snapshot {
    pub cumulative_admitted_bytes: u64,
    pub admission_count: u64,
    pub elapsed_ns: u64,
    pub service_premise_invalidated: bool,
    pub conditional_bounds: Option<ConditionalBounds>,
}
pub struct ArrivalGuard {
    settings: Settings,
    start_ns: u64,
    last_ns: u64,
    end_ns: u64,
    /// Bytes times 1e9: preserves fractional refill without debt or truncation.
    tokens_scaled: u128,
    total: u64,
    count: u64,
    service_invalidated: bool,
}
impl ArrivalGuard {
    pub fn new(settings: Settings, start_ns: u64) -> Result<Self, GuardError> {
        settings.validate()?;
        let end_ns = start_ns
            .checked_add(MAX_LIFETIME_NS)
            .ok_or(GuardError::Overflow)?;
        let tokens_scaled = u128::from(settings.burst_bytes)
            .checked_mul(NS_PER_SECOND)
            .ok_or(GuardError::Overflow)?;
        Ok(Self {
            settings,
            start_ns,
            last_ns: start_ns,
            end_ns,
            tokens_scaled,
            total: 0,
            count: 0,
            service_invalidated: false,
        })
    }
    /// Called with actual read bytes before releasing them into the shaped FIFO.
    /// All refusals leave accounting unchanged. Caller closes/invalidates the
    /// enclosing stream on refusal; there is no wait, borrowing or fallback.
    pub fn admit(&mut self, now_ns: u64, bytes: u64) -> Result<Admission, GuardError> {
        if self.service_invalidated {
            return Err(GuardError::ServiceInvalidated);
        }
        if now_ns < self.last_ns || now_ns >= self.end_ns {
            return Err(GuardError::Clock);
        }
        if bytes == 0 || bytes > self.settings.burst_bytes {
            return Err(GuardError::Arrival);
        }
        if self.count >= MAX_ADMISSIONS {
            return Err(GuardError::Capacity);
        }
        let refill = u128::from(now_ns - self.last_ns)
            .checked_mul(u128::from(self.settings.arrival_rate_bytes_per_second))
            .ok_or(GuardError::Overflow)?;
        let cap = u128::from(self.settings.burst_bytes)
            .checked_mul(NS_PER_SECOND)
            .ok_or(GuardError::Overflow)?;
        let available = self
            .tokens_scaled
            .checked_add(refill)
            .ok_or(GuardError::Overflow)?
            .min(cap);
        let charge = u128::from(bytes)
            .checked_mul(NS_PER_SECOND)
            .ok_or(GuardError::Overflow)?;
        if charge > available {
            return Err(GuardError::BurstExceeded);
        }
        let total = self.total.checked_add(bytes).ok_or(GuardError::Overflow)?;
        let count = self.count.checked_add(1).ok_or(GuardError::Overflow)?;
        self.tokens_scaled = available - charge;
        self.last_ns = now_ns;
        self.total = total;
        self.count = count;
        Ok(Admission {
            admitted_bytes: bytes,
            cumulative_admitted_bytes: total,
            admission_count: count,
            elapsed_ns: now_ns - self.start_ns,
            arrival_envelope_enforced: true,
            guaranteed_service_verified: false,
        })
    }
    pub fn service_failed(&mut self) {
        self.service_invalidated = true;
    }
    /// Even before failure, a conditional theorem is not an observed guarantee.
    /// Historical successful admission receipts certify arrival accounting only.
    pub fn snapshot(&self) -> Result<Snapshot, GuardError> {
        Ok(Snapshot {
            cumulative_admitted_bytes: self.total,
            admission_count: self.count,
            elapsed_ns: self.last_ns - self.start_ns,
            service_premise_invalidated: self.service_invalidated,
            conditional_bounds: if self.service_invalidated {
                None
            } else {
                Some(self.settings.theoretical_bounds()?)
            },
        })
    }
}

#[cfg(test)]
#[path = "network_calculus_guard_tests.rs"]
mod tests;
