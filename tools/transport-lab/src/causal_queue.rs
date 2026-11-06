//! Deterministic, bounded causal shaping model; no socket or product transport.
//!
//! Ticks are abstract time units and bytes are fluid FIFO work. Service consumes
//! real bytes first, then optional padding from spare capacity. This model does
//! not represent TCP packets/ACKs, a cover distribution, or a DP guarantee.
//! A validated rate-latency curve here is a configured service assumption, not
//! a measured guarantee of an Internet route.

use serde::Serialize;
use std::collections::VecDeque;
use thiserror::Error;

const MAX_TICKS: u64 = 100_000;
const MAX_ARRIVALS: usize = 10_000;

#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
pub struct Arrival {
    pub tick: u64,
    pub bytes: u64,
}

/// No service is available in the half-open interval `[start_tick, end_tick)`.
#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
pub struct ServiceOutage {
    pub start_tick: u64,
    pub end_tick: u64,
}

#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum OverflowPolicy {
    DropArrival,
    Stop,
}

#[derive(Clone, Copy, Debug, Serialize)]
pub struct QueueConfig {
    pub max_buffer_bytes: u64,
    pub max_padding_bytes: u64,
    /// Padding credit accrues only from real bytes already sent.
    pub padding_ratio_numerator: u64,
    pub padding_ratio_denominator: u64,
    pub desired_padding_bytes_per_tick: u64,
    pub max_added_delay_ticks: u64,
    /// Consecutive unavailable-service ticks while real bytes are queued.
    pub max_service_gap_ticks: u64,
    pub service_bytes_per_tick: u64,
    pub service_startup_ticks: u64,
    pub overflow_policy: OverflowPolicy,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ModelError {
    #[error("invalid causal queue model: {0}")]
    InvalidInput(&'static str),
    #[error("causal queue model integer overflow")]
    IntegerOverflow,
}

#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum StopReason {
    /// The input trace was processed. Drops still prevent complete delivery.
    Completed,
    BufferOverflow,
    AddedDelayBudget,
    ServiceOutageBudget,
    Horizon,
}

#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
pub struct Emission {
    pub tick: u64,
    pub real_bytes: u64,
    pub padding_bytes: u64,
}

#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
pub struct CompletedArrival {
    pub input_index: usize,
    pub arrival_tick: u64,
    pub departure_tick: u64,
    pub bytes: u64,
}

#[derive(Debug, Serialize)]
pub struct SimulationSummary {
    pub scope: &'static str,
    pub stop_reason: StopReason,
    /// Horizon stops happen at the exclusive end; no bytes emit at that tick.
    pub stopped_at_tick: u64,
    pub input_real_bytes: u64,
    pub observed_real_bytes: u64,
    pub accepted_real_bytes: u64,
    pub sent_real_bytes: u64,
    pub overflow_dropped_real_bytes: u64,
    /// Remaining admitted bytes are cleared on every non-completed stop.
    pub abandoned_real_bytes: u64,
    pub unobserved_real_bytes: u64,
    pub remaining_buffer_bytes: u64,
    pub padding_bytes: u64,
    pub peak_buffer_bytes: u64,
    pub max_departed_byte_delay_ticks: u64,
    pub conservation_ok: bool,
    pub all_real_delivered: bool,
    pub emissions: Vec<Emission>,
    pub completed_arrivals: Vec<CompletedArrival>,
}

struct Pending {
    index: usize,
    arrival: Arrival,
    remaining: u64,
}

fn add(a: u64, b: u64) -> Result<u64, ModelError> {
    a.checked_add(b).ok_or(ModelError::IntegerOverflow)
}

fn validate(
    config: &QueueConfig,
    arrivals: &[Arrival],
    outages: &[ServiceOutage],
    horizon_ticks: u64,
) -> Result<u64, ModelError> {
    if config.max_buffer_bytes == 0
        || config.service_bytes_per_tick == 0
        || config.padding_ratio_denominator == 0
        || horizon_ticks == 0
        || horizon_ticks > MAX_TICKS
        || arrivals.len() > MAX_ARRIVALS
        || outages.len() > MAX_ARRIVALS
    {
        return Err(ModelError::InvalidInput(
            "zero capacity or work limit exceeded",
        ));
    }
    let mut total = 0;
    for (i, arrival) in arrivals.iter().enumerate() {
        if arrival.bytes == 0 || (i > 0 && arrivals[i - 1].tick > arrival.tick) {
            return Err(ModelError::InvalidInput(
                "arrivals must be nonempty and ordered",
            ));
        }
        total = add(total, arrival.bytes)?;
    }
    for (i, outage) in outages.iter().enumerate() {
        if outage.start_tick >= outage.end_tick
            || (i > 0 && outages[i - 1].end_tick > outage.start_tick)
        {
            return Err(ModelError::InvalidInput(
                "outages must be disjoint and ordered",
            ));
        }
    }
    Ok(total)
}

/// Simulate `[0, horizon_ticks)` and clear pending work at any terminal stop.
/// No input bytes enter the queue before their arrival tick, and neither
/// padding nor dropped bytes are credited as real output.
pub fn simulate(
    config: &QueueConfig,
    arrivals: &[Arrival],
    outages: &[ServiceOutage],
    horizon_ticks: u64,
) -> Result<SimulationSummary, ModelError> {
    let total = validate(config, arrivals, outages, horizon_ticks)?;
    let mut result = SimulationSummary {
        scope: "deterministic_local_queue_model_only",
        stop_reason: StopReason::Horizon,
        stopped_at_tick: horizon_ticks,
        input_real_bytes: total,
        observed_real_bytes: 0,
        accepted_real_bytes: 0,
        sent_real_bytes: 0,
        overflow_dropped_real_bytes: 0,
        abandoned_real_bytes: 0,
        unobserved_real_bytes: total,
        remaining_buffer_bytes: 0,
        padding_bytes: 0,
        peak_buffer_bytes: 0,
        max_departed_byte_delay_ticks: 0,
        conservation_ok: false,
        all_real_delivered: false,
        emissions: Vec::new(),
        completed_arrivals: Vec::new(),
    };
    let mut queue: VecDeque<Pending> = VecDeque::new();
    let mut next_arrival = 0;
    let mut next_outage = 0;
    let mut service_gap = 0_u64;

    'ticks: for tick in 0..horizon_ticks {
        // The timestamp is the only information read from a future arrival.
        while next_arrival < arrivals.len() && arrivals[next_arrival].tick <= tick {
            let arrival = arrivals[next_arrival];
            let index = next_arrival;
            next_arrival += 1;
            result.observed_real_bytes = add(result.observed_real_bytes, arrival.bytes)?;
            if arrival.bytes > config.max_buffer_bytes - result.remaining_buffer_bytes {
                result.overflow_dropped_real_bytes =
                    add(result.overflow_dropped_real_bytes, arrival.bytes)?;
                if config.overflow_policy == OverflowPolicy::Stop {
                    result.stop_reason = StopReason::BufferOverflow;
                    result.stopped_at_tick = tick;
                    break 'ticks;
                }
                continue;
            }
            result.accepted_real_bytes = add(result.accepted_real_bytes, arrival.bytes)?;
            result.remaining_buffer_bytes += arrival.bytes;
            result.peak_buffer_bytes = result.peak_buffer_bytes.max(result.remaining_buffer_bytes);
            queue.push_back(Pending {
                index,
                arrival,
                remaining: arrival.bytes,
            });
        }
        if queue
            .front()
            .is_some_and(|p| tick - p.arrival.tick > config.max_added_delay_ticks)
        {
            result.stop_reason = StopReason::AddedDelayBudget;
            result.stopped_at_tick = tick;
            break;
        }
        while next_outage < outages.len() && outages[next_outage].end_tick <= tick {
            next_outage += 1;
        }
        let unavailable = tick < config.service_startup_ticks
            || outages
                .get(next_outage)
                .is_some_and(|o| o.start_tick <= tick);
        let capacity = if unavailable {
            0
        } else {
            config.service_bytes_per_tick
        };
        if capacity == 0 && !queue.is_empty() {
            service_gap = add(service_gap, 1)?;
            if service_gap > config.max_service_gap_ticks {
                result.stop_reason = StopReason::ServiceOutageBudget;
                result.stopped_at_tick = tick;
                break;
            }
        } else {
            service_gap = 0;
        }

        let mut remaining_capacity = capacity;
        let mut emitted_real = 0;
        while remaining_capacity > 0 {
            let Some(pending) = queue.front_mut() else {
                break;
            };
            let sent = pending.remaining.min(remaining_capacity);
            pending.remaining -= sent;
            remaining_capacity -= sent;
            result.remaining_buffer_bytes -= sent;
            emitted_real += sent;
            result.max_departed_byte_delay_ticks = result
                .max_departed_byte_delay_ticks
                .max(tick - pending.arrival.tick);
            if pending.remaining == 0 {
                let done = queue.pop_front().expect("front was just serviced");
                result.completed_arrivals.push(CompletedArrival {
                    input_index: done.index,
                    arrival_tick: done.arrival.tick,
                    departure_tick: tick,
                    bytes: done.arrival.bytes,
                });
            }
        }
        result.sent_real_bytes = add(result.sent_real_bytes, emitted_real)?;
        let ratio_limit = (u128::from(result.sent_real_bytes)
            * u128::from(config.padding_ratio_numerator)
            / u128::from(config.padding_ratio_denominator))
        .min(u128::from(u64::MAX)) as u64;
        let available_padding = config
            .max_padding_bytes
            .min(ratio_limit)
            .saturating_sub(result.padding_bytes);
        let emitted_padding = remaining_capacity
            .min(config.desired_padding_bytes_per_tick)
            .min(available_padding);
        result.padding_bytes = add(result.padding_bytes, emitted_padding)?;
        if emitted_real > 0 || emitted_padding > 0 {
            result.emissions.push(Emission {
                tick,
                real_bytes: emitted_real,
                padding_bytes: emitted_padding,
            });
        }
        if next_arrival == arrivals.len() && queue.is_empty() {
            result.stop_reason = StopReason::Completed;
            result.stopped_at_tick = tick;
            break;
        }
    }
    result.abandoned_real_bytes = result.remaining_buffer_bytes;
    queue.clear();
    result.remaining_buffer_bytes = 0;
    result.unobserved_real_bytes = total - result.observed_real_bytes;
    let accounted = add(
        add(result.sent_real_bytes, result.overflow_dropped_real_bytes)?,
        add(result.abandoned_real_bytes, result.unobserved_real_bytes)?,
    )?;
    result.conservation_ok = accounted == total
        && add(result.sent_real_bytes, result.abandoned_real_bytes)? == result.accepted_real_bytes;
    result.all_real_delivered = result.stop_reason == StopReason::Completed
        && result.sent_real_bytes == result.input_real_bytes;
    Ok(result)
}

#[derive(Clone, Copy, Debug, Serialize)]
pub struct ArrivalEnvelope {
    pub burst_bytes: u64,
    pub rate_bytes_per_tick: u64,
}

#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
pub struct NetworkCalculusBounds {
    pub scope: &'static str,
    pub backlog_bytes: u64,
    pub delay_ticks_ceiling: u64,
}

#[derive(Debug, Error, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BoundRejection {
    #[error("invalid simulator input")]
    InvalidInput,
    #[error("arrival curve assumption is not satisfied")]
    ArrivalEnvelope,
    #[error("arrival rate exceeds guaranteed service rate")]
    UnstableRate,
    #[error("service outage invalidates the configured rate-latency guarantee")]
    ServiceOutage,
    #[error("model budgets can terminate before the bound is attained")]
    BudgetTruncatesService,
    #[error("simulation horizon truncates the guaranteed service")]
    HorizonTruncatesService,
    #[error("bound exceeds integer representation")]
    IntegerOverflow,
}

/// Check the discrete token bucket `alpha(t) = b + r*t` and uninterrupted
/// configured service `beta(t) = R * max(t-T, 0)`. Returns conservative integer
/// bounds `B <= b+r*T` and `D <= ceil(T+b/R)` only after their assumptions and
/// sufficient buffer, delay, outage and horizon budgets have been checked.
pub fn network_calculus_bound(
    config: &QueueConfig,
    envelope: ArrivalEnvelope,
    arrivals: &[Arrival],
    outages: &[ServiceOutage],
    horizon_ticks: u64,
) -> Result<NetworkCalculusBounds, BoundRejection> {
    validate(config, arrivals, outages, horizon_ticks).map_err(|_| BoundRejection::InvalidInput)?;
    if !outages.is_empty() {
        return Err(BoundRejection::ServiceOutage);
    }
    if envelope.rate_bytes_per_tick > config.service_bytes_per_tick {
        return Err(BoundRejection::UnstableRate);
    }
    let mut tokens = u128::from(envelope.burst_bytes);
    let mut previous_tick = 0;
    for arrival in arrivals {
        tokens = (tokens
            + u128::from(arrival.tick - previous_tick) * u128::from(envelope.rate_bytes_per_tick))
        .min(u128::from(envelope.burst_bytes));
        if u128::from(arrival.bytes) > tokens {
            return Err(BoundRejection::ArrivalEnvelope);
        }
        tokens -= u128::from(arrival.bytes);
        previous_tick = arrival.tick;
    }
    let backlog = u128::from(envelope.burst_bytes)
        + u128::from(envelope.rate_bytes_per_tick) * u128::from(config.service_startup_ticks);
    let rate = u128::from(config.service_bytes_per_tick);
    let delay =
        u128::from(config.service_startup_ticks) + u128::from(envelope.burst_bytes).div_ceil(rate);
    let backlog = u64::try_from(backlog).map_err(|_| BoundRejection::IntegerOverflow)?;
    let delay = u64::try_from(delay).map_err(|_| BoundRejection::IntegerOverflow)?;
    if config.max_buffer_bytes < backlog
        || config.max_added_delay_ticks < delay
        || config.max_service_gap_ticks < config.service_startup_ticks
    {
        return Err(BoundRejection::BudgetTruncatesService);
    }
    if arrivals
        .last()
        .is_some_and(|a| u128::from(a.tick) + u128::from(delay) + 1 > u128::from(horizon_ticks))
    {
        return Err(BoundRejection::HorizonTruncatesService);
    }
    Ok(NetworkCalculusBounds {
        scope: "configured_model_service_guarantee_only_not_measured_network",
        backlog_bytes: backlog,
        delay_ticks_ceiling: delay,
    })
}

#[derive(Debug, Serialize)]
pub struct QueueDemo {
    pub scope: &'static str,
    pub config: QueueConfig,
    pub arrival_envelope: ArrivalEnvelope,
    pub shaped: SimulationSummary,
    pub checked_model_bounds: NetworkCalculusBounds,
    pub service_outage: SimulationSummary,
    pub outage_bound_rejection: BoundRejection,
}

/// A small serializable example with a successful model and a stopped outage.
pub fn demo() -> Result<QueueDemo, ModelError> {
    let config = QueueConfig {
        max_buffer_bytes: 192,
        max_padding_bytes: 128,
        padding_ratio_numerator: 1,
        padding_ratio_denominator: 2,
        desired_padding_bytes_per_tick: 32,
        max_added_delay_ticks: 4,
        max_service_gap_ticks: 2,
        service_bytes_per_tick: 64,
        service_startup_ticks: 2,
        overflow_policy: OverflowPolicy::DropArrival,
    };
    let arrivals = [
        Arrival {
            tick: 0,
            bytes: 128,
        },
        Arrival { tick: 2, bytes: 32 },
        Arrival { tick: 5, bytes: 64 },
    ];
    let envelope = ArrivalEnvelope {
        burst_bytes: 128,
        rate_bytes_per_tick: 32,
    };
    let outages = [ServiceOutage {
        start_tick: 2,
        end_tick: 8,
    }];
    let bounds = network_calculus_bound(&config, envelope, &arrivals, &[], 16)
        .map_err(|_| ModelError::InvalidInput("demo service assumptions failed"))?;
    let rejection = network_calculus_bound(&config, envelope, &arrivals, &outages, 16)
        .err()
        .ok_or(ModelError::InvalidInput("outage incorrectly certified"))?;
    Ok(QueueDemo {
        scope: "simulation_only_no_privacy_or_reachability_claim",
        config,
        arrival_envelope: envelope,
        shaped: simulate(&config, &arrivals, &[], 16)?,
        checked_model_bounds: bounds,
        service_outage: simulate(&config, &arrivals, &outages, 16)?,
        outage_bound_rejection: rejection,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> QueueConfig {
        QueueConfig {
            max_buffer_bytes: 16,
            max_padding_bytes: 5,
            padding_ratio_numerator: 1,
            padding_ratio_denominator: 2,
            desired_padding_bytes_per_tick: 8,
            max_added_delay_ticks: 8,
            max_service_gap_ticks: 3,
            service_bytes_per_tick: 8,
            service_startup_ticks: 0,
            overflow_policy: OverflowPolicy::DropArrival,
        }
    }

    #[test]
    fn overflow_drops_whole_arrival_and_preserves_fifo() {
        let arrivals = [
            Arrival { tick: 0, bytes: 12 },
            Arrival { tick: 0, bytes: 5 },
            Arrival { tick: 1, bytes: 4 },
        ];
        let result = simulate(&config(), &arrivals, &[], 8).unwrap();
        assert_eq!(result.stop_reason, StopReason::Completed);
        assert_eq!(result.overflow_dropped_real_bytes, 5);
        assert_eq!(result.sent_real_bytes, 16);
        assert_eq!(result.peak_buffer_bytes, 12);
        assert_eq!(
            result
                .completed_arrivals
                .iter()
                .map(|a| a.input_index)
                .collect::<Vec<_>>(),
            vec![0, 2]
        );
        assert!(result.conservation_ok);
        assert!(!result.all_real_delivered);
        let mut stopping = config();
        stopping.overflow_policy = OverflowPolicy::Stop;
        let stopped = simulate(&stopping, &arrivals, &[], 8).unwrap();
        assert_eq!(stopped.stop_reason, StopReason::BufferOverflow);
        assert_eq!(
            (stopped.abandoned_real_bytes, stopped.unobserved_real_bytes),
            (12, 4)
        );
        assert_eq!(stopped.remaining_buffer_bytes, 0);
        assert!(stopped.conservation_ok);
    }

    #[test]
    fn padding_obeys_both_absolute_and_causal_real_ratio_budgets() {
        let arrivals = [Arrival { tick: 0, bytes: 4 }, Arrival { tick: 8, bytes: 8 }];
        let result = simulate(&config(), &arrivals, &[], 16).unwrap();
        let mut real = 0;
        let mut padding = 0;
        for emission in &result.emissions {
            real += emission.real_bytes;
            padding += emission.padding_bytes;
            assert!(padding <= real / 2);
            assert!(padding <= 5);
            assert!(emission.real_bytes + emission.padding_bytes <= 8);
        }
        assert_eq!(padding, 2);
        let mut absolute_limited = config();
        absolute_limited.max_padding_bytes = 1;
        let limited = simulate(&absolute_limited, &arrivals, &[], 16).unwrap();
        assert_eq!(limited.padding_bytes, 1);
    }

    #[test]
    fn no_future_real_or_padding_credit_is_generated() {
        let arrivals = [
            Arrival { tick: 4, bytes: 13 },
            Arrival { tick: 8, bytes: 6 },
        ];
        let result = simulate(&config(), &arrivals, &[], 16).unwrap();
        let mut departed = 0;
        for emission in &result.emissions {
            let available: u64 = arrivals
                .iter()
                .filter(|a| a.tick <= emission.tick)
                .map(|a| a.bytes)
                .sum();
            departed += emission.real_bytes;
            assert!(departed <= available);
            assert!(emission.tick >= 4);
        }
        assert_eq!(result.sent_real_bytes, 19);
        assert!(result.conservation_ok);
        assert_eq!(simulate(&config(), &[], &[], 4).unwrap().padding_bytes, 0);
    }

    #[test]
    fn delay_budget_stops_before_emitting_overdue_bytes() {
        let mut cfg = config();
        cfg.max_added_delay_ticks = 0;
        let result = simulate(&cfg, &[Arrival { tick: 0, bytes: 16 }], &[], 8).unwrap();
        assert_eq!(result.stop_reason, StopReason::AddedDelayBudget);
        assert_eq!(result.stopped_at_tick, 1);
        assert_eq!(
            (result.sent_real_bytes, result.abandoned_real_bytes),
            (8, 8)
        );
        assert_eq!(result.max_departed_byte_delay_ticks, 0);
        assert_eq!(result.remaining_buffer_bytes, 0);
        assert!(result.conservation_ok);
    }

    #[test]
    fn blocked_service_and_horizon_clear_all_pending_bytes() {
        let arrivals = [Arrival { tick: 0, bytes: 8 }, Arrival { tick: 7, bytes: 4 }];
        let outage = [ServiceOutage {
            start_tick: 0,
            end_tick: 8,
        }];
        let result = simulate(&config(), &arrivals, &outage, 16).unwrap();
        assert_eq!(result.stop_reason, StopReason::ServiceOutageBudget);
        assert_eq!(result.stopped_at_tick, 3);
        assert_eq!(
            (
                result.sent_real_bytes,
                result.abandoned_real_bytes,
                result.unobserved_real_bytes
            ),
            (0, 8, 4)
        );
        assert_eq!(result.remaining_buffer_bytes, 0);
        assert!(result.conservation_ok);
        let horizon = simulate(&config(), &arrivals, &outage, 2).unwrap();
        assert_eq!(horizon.stop_reason, StopReason::Horizon);
        assert_eq!(horizon.stopped_at_tick, 2);
        assert_eq!(horizon.remaining_buffer_bytes, 0);
        assert!(horizon.conservation_ok);
    }

    #[test]
    fn checked_service_curve_bounds_apply_and_outages_invalidate_them() {
        let result = demo().unwrap();
        assert_eq!(result.checked_model_bounds.backlog_bytes, 192);
        assert_eq!(result.checked_model_bounds.delay_ticks_ceiling, 4);
        assert_eq!(result.shaped.stop_reason, StopReason::Completed);
        assert!(result.shaped.all_real_delivered);
        assert!(result.shaped.peak_buffer_bytes <= result.checked_model_bounds.backlog_bytes);
        assert!(
            result.shaped.max_departed_byte_delay_ticks
                <= result.checked_model_bounds.delay_ticks_ceiling
        );
        assert_eq!(result.outage_bound_rejection, BoundRejection::ServiceOutage);
        assert_eq!(
            result.service_outage.stop_reason,
            StopReason::ServiceOutageBudget
        );
        let cfg = config();
        let invalid = network_calculus_bound(
            &cfg,
            ArrivalEnvelope {
                burst_bytes: 8,
                rate_bytes_per_tick: 1,
            },
            &[Arrival { tick: 0, bytes: 9 }],
            &[],
            16,
        );
        assert_eq!(invalid, Err(BoundRejection::ArrivalEnvelope));
        let unstable = network_calculus_bound(
            &cfg,
            ArrivalEnvelope {
                burst_bytes: 8,
                rate_bytes_per_tick: 9,
            },
            &[],
            &[],
            16,
        );
        assert_eq!(unstable, Err(BoundRejection::UnstableRate));
        let truncated = network_calculus_bound(
            &cfg,
            ArrivalEnvelope {
                burst_bytes: 8,
                rate_bytes_per_tick: 1,
            },
            &[Arrival { tick: 0, bytes: 8 }],
            &[],
            1,
        );
        assert_eq!(truncated, Err(BoundRejection::HorizonTruncatesService));
    }
}
