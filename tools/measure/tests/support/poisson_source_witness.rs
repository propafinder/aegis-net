//! Test-only aggregate observations, relative to the parent's READY read.
//! Neither nominal ticks nor send returns establish child arrivals/departures.
use serde_json::{json, Value};

const PERIOD_NS: u64 = 2_000_000;

#[derive(Default)]
pub struct SourceWitness {
    ticks: u64,
    offered: u64,
    last_nominal: Option<u64>,
    skipped: u64,
    invalid_grid: bool,
    invalid_clock_order: bool,
    early_dispatches: u64,
    max_dispatch_lateness: u64,
    max_send_bracket: u64,
    first_offer: Option<u64>,
    last_offer: Option<u64>,
    max_offer_gap: u64,
}

impl SourceWitness {
    pub fn tick(&mut self, nominal_ns: u64, dispatched_ns: u64) {
        self.ticks = self.ticks.saturating_add(1);
        if let Some(previous) = self.last_nominal {
            match nominal_ns.checked_sub(previous) {
                Some(delta) if delta >= PERIOD_NS && delta % PERIOD_NS == 0 => {
                    self.skipped = self.skipped.saturating_add(delta / PERIOD_NS - 1);
                }
                _ => self.invalid_grid = true,
            }
        } else if nominal_ns != 0 {
            self.invalid_grid = true;
        }
        self.last_nominal = Some(nominal_ns);
        match dispatched_ns.checked_sub(nominal_ns) {
            Some(late) => self.max_dispatch_lateness = self.max_dispatch_lateness.max(late),
            None => self.early_dispatches = self.early_dispatches.saturating_add(1),
        }
    }

    pub fn sent(&mut self, dispatched_ns: u64, returned_ns: u64) {
        self.offered = self.offered.saturating_add(1);
        match returned_ns.checked_sub(dispatched_ns) {
            Some(bracket) => self.max_send_bracket = self.max_send_bracket.max(bracket),
            None => self.invalid_clock_order = true,
        }
        if let Some(previous) = self.last_offer {
            if dispatched_ns < previous {
                self.invalid_clock_order = true;
            }
            match returned_ns.checked_sub(previous) {
                Some(gap) => self.max_offer_gap = self.max_offer_gap.max(gap),
                None => self.invalid_clock_order = true,
            }
        } else {
            self.first_offer = Some(returned_ns);
        }
        self.last_offer = Some(returned_ns);
    }

    pub fn report(&self) -> Value {
        json!({
            "clock_origin": "parent_ready_observation",
            "tick_count": self.ticks,
            "successful_application_send_returns": self.offered,
            "nominal_ticks_skipped": (!self.invalid_grid).then_some(self.skipped),
            "nominal_grid_valid": !self.invalid_grid,
            "observation_clock_order_valid": !self.invalid_clock_order,
            "early_tick_dispatches": self.early_dispatches,
            "maximum_tick_dispatch_lateness_ns": self.max_dispatch_lateness,
            "maximum_successful_application_send_bracket_ns": (!self.invalid_clock_order).then_some(self.max_send_bracket),
            "first_successful_send_return_ns": self.first_offer,
            "last_successful_send_return_ns": self.last_offer,
            "maximum_successful_send_return_gap_ns": (!self.invalid_clock_order && self.offered >= 2).then_some(self.max_offer_gap),
            "child_ready_emission_lag_verified": false,
            "child_source_arrivals_verified": false,
            "physical_packet_departures_verified": false,
            "poisson_source_verified": false,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn skip_grid_and_actual_offer_brackets_are_distinct() {
        let mut w = SourceWitness::default();
        w.tick(0, 100);
        w.sent(100, 200);
        w.tick(2_000_000, 18_000_000);
        w.sent(18_000_000, 19_000_000);
        w.tick(20_000_000, 21_000_000);
        w.sent(21_000_000, 21_200_000);
        let r = w.report();
        assert_eq!(r["nominal_ticks_skipped"], 8);
        assert_eq!(r["maximum_tick_dispatch_lateness_ns"], 16_000_000);
        assert_eq!(
            r["maximum_successful_application_send_bracket_ns"],
            1_000_000
        );
        assert_eq!(r["maximum_successful_send_return_gap_ns"], 18_999_800);
        assert_eq!(r["successful_application_send_returns"], 3);
        assert_eq!(r["child_source_arrivals_verified"], false);
        assert_eq!(r["child_ready_emission_lag_verified"], false);
    }

    #[test]
    fn no_offer_is_unknown_not_a_zero_time_arrival() {
        let r = SourceWitness::default().report();
        assert!(r["first_successful_send_return_ns"].is_null());
        assert!(r["last_successful_send_return_ns"].is_null());
        assert!(r["maximum_successful_send_return_gap_ns"].is_null());
        assert_eq!(r["tick_count"], 0);
        assert_eq!(r["successful_application_send_returns"], 0);
    }

    #[test]
    fn malformed_grid_or_backward_observation_does_not_certify_counts() {
        let mut w = SourceWitness::default();
        w.tick(1, 0);
        w.sent(10, 9);
        w.tick(1, 10);
        w.sent(10, 8);
        let r = w.report();
        assert!(r["nominal_ticks_skipped"].is_null());
        assert!(r["maximum_successful_application_send_bracket_ns"].is_null());
        assert!(r["maximum_successful_send_return_gap_ns"].is_null());
        assert_eq!(r["nominal_grid_valid"], false);
        assert_eq!(r["observation_clock_order_valid"], false);
        assert_eq!(r["early_tick_dispatches"], 1);
        let mut w = SourceWitness::default();
        w.sent(0, 10);
        w.sent(5, 11);
        assert_eq!(w.report()["observation_clock_order_valid"], false);
    }
}
