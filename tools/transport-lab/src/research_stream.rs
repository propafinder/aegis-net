//! Bounded BIT-TRAPS whole-sequence model and declared finite service-grid caller.
use aegis_core::traffic_privacy::bittraps::{
    finite_stream_law, optimize_service_grid, FiniteStreamModel,
};
use serde::Deserialize;
use serde_json::{json, Value};
use std::io;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub model: FiniteStreamModel,
    pub candidates: Vec<Vec<(usize, f64)>>,
    pub max_padding: f64,
    pub max_queue_area: f64,
    pub max_tail: f64,
}

pub fn analyze(request: Request) -> io::Result<Value> {
    let refuse = || {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "finite stream grid work exceeds admission",
        )
    };
    let m = &request.model;
    if m.horizon > 6 || request.candidates.is_empty() || request.candidates.len() > 32 {
        return Err(refuse());
    }
    // Admission precedes every enumeration, including the baseline. Bound total
    // work across all candidates, not just each individually valid subproblem.
    let mut total = 0usize;
    for service_count in
        std::iter::once(m.service.len()).chain(request.candidates.iter().map(Vec::len))
    {
        let paths = m
            .arrival_sizes
            .len()
            .checked_mul(service_count)
            .and_then(|x| x.checked_pow(m.horizon as u32))
            .ok_or_else(refuse)?;
        total = total
            .checked_add(paths)
            .filter(|n| *n <= 1_048_576)
            .ok_or_else(refuse)?;
    }
    let baseline = finite_stream_law(m)?;
    let (index, selected) = optimize_service_grid(
        m,
        &request.candidates,
        request.max_padding,
        request.max_queue_area,
        request.max_tail,
    )?;
    Ok(json!({
        "schema": "aegis_bittraps_finite_stream_grid_v1",
        "scope": "whole finite Markov sequence law with observable overflow; declared finite grid only",
        "baseline": baseline, "selected_candidate": index, "selected": selected,
        "candidate_service": request.candidates[index], "enumeration_work": total,
        "stationary_rate_proven": false, "target_network_measured": false,
        "installed_runtime": false, "beta_exit": false,
    }))
}
