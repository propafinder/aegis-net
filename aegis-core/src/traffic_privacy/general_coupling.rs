//! Exact rational couplings and bounded multi-block iterative cover coding.
//! Joint marginals are certified with integers. Greedy allocation approximates
//! minimum entropy; it does not certify the NP-hard global optimum. Encoding
//! takes already uniformly masked bytes, never plaintext or TLS session keys.
use rand::{CryptoRng, RngCore};
use std::{cmp::Reverse, collections::BinaryHeap, io};

pub const MAX_ALPHABET: usize = 256;
pub const MAX_BLOCKS: usize = 274;
pub const MAX_HORIZON: usize = 4096;
const MAX_MASS: u128 = 1 << 80;

fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        "finite coupling bound or mass invalid",
    )
}
fn malformed() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "invalid or unresolved cover transcript",
    )
}
fn gcd(mut a: u128, mut b: u128) -> u128 {
    while b != 0 {
        (a, b) = (b, a % b);
    }
    a
}

/// Canonical nonnegative rational probabilities, including explicit zero states.
/// No float rounding, normalization tolerance, or positive-mass truncation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FiniteDistribution {
    weights: Vec<u128>,
    total: u128,
}
impl FiniteDistribution {
    pub fn new(weights: Vec<u64>) -> io::Result<Self> {
        Self::from_masses(weights.into_iter().map(u128::from).collect())
    }
    /// Public for replay of an exact posterior; same bounds as initial models.
    pub fn from_masses(mut weights: Vec<u128>) -> io::Result<Self> {
        if weights.is_empty() || weights.len() > MAX_ALPHABET {
            return Err(invalid());
        }
        let divisor = weights.iter().copied().fold(0, gcd);
        if divisor == 0 {
            return Err(invalid());
        }
        for weight in &mut weights {
            *weight /= divisor;
        }
        let total = weights
            .iter()
            .try_fold(0u128, |s, w| s.checked_add(*w))
            .ok_or_else(invalid)?;
        if total > MAX_MASS {
            return Err(invalid());
        }
        Ok(Self { weights, total })
    }
    pub fn weights(&self) -> &[u128] {
        &self.weights
    }
    pub fn total(&self) -> u128 {
        self.total
    }
    /// Exact point mass only. No MAP estimate or entropy threshold is decoded.
    pub fn resolved_symbol(&self) -> Option<usize> {
        self.weights.iter().position(|w| *w == self.total)
    }
    /// Deterministic Q32 Shannon-entropy estimate for iMEC block selection.
    /// Approximation affects efficiency/which block is chosen, not certificates.
    pub fn entropy_score_q32(&self) -> u128 {
        let weighted_logs: u128 = self
            .weights
            .iter()
            .filter(|w| **w != 0)
            .map(|w| *w * log2_q32(*w))
            .sum(); // <= 2^80 * (80 * 2^32), strictly below u128::MAX
        log2_q32(self.total).saturating_sub(weighted_logs / self.total)
    }
}

// Normalize to Q63, then square to extract 32 binary fractional logarithm bits.
// Every multiplication fits u128, and integer behavior is platform independent.
fn log2_q32(value: u128) -> u128 {
    debug_assert!(value != 0 && value <= MAX_MASS);
    let exponent = 127 - value.leading_zeros();
    let mut x = if exponent > 63 {
        value >> (exponent - 63)
    } else {
        value << (63 - exponent)
    };
    let mut fraction = 0;
    for bit in (0..32).rev() {
        x = (x * x) >> 63;
        if x >= 1 << 64 {
            x >>= 1;
            fraction |= 1u128 << bit;
        }
    }
    (u128::from(exponent) << 32) | fraction
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JointMass {
    pub message: usize,
    pub cover: usize,
    pub mass: u128,
}

/// Largest-remaining-mass greedy approximation (Kocaoglu et al., Algorithm 1).
/// Sparse support contains at most m+n-1 cells, including unequal alphabets.
#[derive(Clone, Debug)]
pub struct GreedyCoupling {
    message: FiniteDistribution,
    cover: FiniteDistribution,
    denominator: u128,
    cells: Vec<JointMass>,
}
impl GreedyCoupling {
    pub fn new(message: FiniteDistribution, cover: FiniteDistribution) -> io::Result<Self> {
        let denominator = (message.total / gcd(message.total, cover.total))
            .checked_mul(cover.total)
            .filter(|v| *v <= MAX_MASS)
            .ok_or_else(invalid)?;
        let mut left = BinaryHeap::new();
        let mut right = BinaryHeap::new();
        for (i, w) in message.weights.iter().enumerate().filter(|(_, w)| **w != 0) {
            left.push((*w * (denominator / message.total), Reverse(i)));
        }
        for (i, w) in cover.weights.iter().enumerate().filter(|(_, w)| **w != 0) {
            right.push((*w * (denominator / cover.total), Reverse(i)));
        }
        let mut cells = Vec::with_capacity(message.weights.len() + cover.weights.len() - 1);
        while let (Some((a, Reverse(i))), Some((b, Reverse(j)))) = (left.pop(), right.pop()) {
            let mass = a.min(b);
            cells.push(JointMass {
                message: i,
                cover: j,
                mass,
            });
            if a > mass {
                left.push((a - mass, Reverse(i)));
            }
            if b > mass {
                right.push((b - mass, Reverse(j)));
            }
        }
        let result = Self {
            message,
            cover,
            denominator,
            cells,
        };
        result.certify_marginals()?;
        Ok(result)
    }
    pub fn denominator(&self) -> u128 {
        self.denominator
    }
    pub fn cells(&self) -> &[JointMass] {
        &self.cells
    }
    /// Recompute every exact row/column sum. This certifies marginals, not MEC.
    pub fn certify_marginals(&self) -> io::Result<()> {
        let mut rows = vec![0u128; self.message.weights.len()];
        let mut columns = vec![0u128; self.cover.weights.len()];
        for cell in &self.cells {
            if cell.mass == 0 || cell.message >= rows.len() || cell.cover >= columns.len() {
                return Err(malformed());
            }
            rows[cell.message] = rows[cell.message]
                .checked_add(cell.mass)
                .ok_or_else(malformed)?;
            columns[cell.cover] = columns[cell.cover]
                .checked_add(cell.mass)
                .ok_or_else(malformed)?;
        }
        if rows
            .iter()
            .zip(&self.message.weights)
            .any(|(s, w)| *s != *w * (self.denominator / self.message.total))
            || columns
                .iter()
                .zip(&self.cover.weights)
                .any(|(s, w)| *s != *w * (self.denominator / self.cover.total))
            || self.cells.len() > rows.len() + columns.len() - 1
        {
            return Err(malformed());
        }
        Ok(())
    }
    /// Conditional cover draw given a supported message. Entropy failure refuses;
    /// caller must not regenerate/choose only successfully decodable transcripts.
    pub fn encode<R: RngCore + CryptoRng>(&self, message: usize, rng: &mut R) -> io::Result<usize> {
        let weight = *self.message.weights.get(message).ok_or_else(invalid)?;
        if weight == 0 {
            return Err(invalid());
        }
        let mut draw = uniform_below(rng, weight * (self.denominator / self.message.total))?;
        for cell in self.cells.iter().filter(|cell| cell.message == message) {
            if draw < cell.mass {
                return Ok(cell.cover);
            }
            draw -= cell.mass;
        }
        Err(malformed())
    }
    /// Exact Bayesian posterior for the observed cover column.
    pub fn posterior(&self, symbol: usize) -> io::Result<FiniteDistribution> {
        if symbol >= self.cover.weights.len() || self.cover.weights[symbol] == 0 {
            return Err(malformed());
        }
        let mut weights = vec![0u128; self.message.weights.len()];
        for cell in self.cells.iter().filter(|cell| cell.cover == symbol) {
            weights[cell.message] = cell.mass;
        }
        FiniteDistribution::from_masses(weights).map_err(|_| malformed())
    }
}

fn uniform_below<R: RngCore + CryptoRng>(rng: &mut R, upper: u128) -> io::Result<u128> {
    if upper == 0 {
        return Err(invalid());
    }
    let threshold = upper.wrapping_neg() % upper;
    for _ in 0..128 {
        let mut bytes = [0; 16];
        rng.try_fill_bytes(&mut bytes)
            .map_err(|_| io::Error::other("cryptographic entropy unavailable"))?;
        let draw = u128::from_le_bytes(bytes);
        if draw >= threshold {
            return Ok(draw % upper);
        }
    }
    Err(io::Error::other("coupling entropy draw budget exhausted"))
}

/// Per-record iMEC state: independent uniform message blocks at initialization.
/// Encoding and decoding choose the same maximal estimated-entropy block and
/// update only that block with the observed coupling column. The cover model
/// may be supplied conditionally at each step; peers must supply the same model.
pub struct IterativeCoupling {
    posteriors: Vec<FiniteDistribution>,
    entropy_scores: Vec<u128>,
    steps: usize,
}
impl IterativeCoupling {
    pub fn new(blocks: usize, alphabet: usize) -> io::Result<Self> {
        if !(1..=MAX_BLOCKS).contains(&blocks) || !(1..=MAX_ALPHABET).contains(&alphabet) {
            return Err(invalid());
        }
        let initial = FiniteDistribution::new(vec![1; alphabet])?;
        let score = initial.entropy_score_q32();
        Ok(Self {
            posteriors: vec![initial; blocks],
            entropy_scores: vec![score; blocks],
            steps: 0,
        })
    }
    /// First index wins ties, including public padding after all blocks resolve.
    pub fn next_block(&self) -> usize {
        let mut winner = 0;
        for i in 1..self.entropy_scores.len() {
            if self.entropy_scores[i] > self.entropy_scores[winner] {
                winner = i;
            }
        }
        winner
    }
    pub fn posteriors(&self) -> &[FiniteDistribution] {
        &self.posteriors
    }
    fn apply(&mut self, block: usize, coupling: &GreedyCoupling, symbol: usize) -> io::Result<()> {
        let posterior = coupling.posterior(symbol)?;
        self.entropy_scores[block] = posterior.entropy_score_q32();
        self.posteriors[block] = posterior;
        self.steps += 1;
        Ok(())
    }
    pub fn encode_step<R: RngCore + CryptoRng>(
        &mut self,
        message: &[usize],
        cover: FiniteDistribution,
        rng: &mut R,
    ) -> io::Result<usize> {
        if self.steps >= MAX_HORIZON
            || message.len() != self.posteriors.len()
            || message
                .iter()
                .zip(&self.posteriors)
                .any(|(s, p)| p.weights.get(*s).is_none_or(|w| *w == 0))
        {
            return Err(invalid());
        }
        let block = self.next_block();
        let coupling = GreedyCoupling::new(self.posteriors[block].clone(), cover)?;
        let symbol = coupling.encode(message[block], rng)?;
        self.apply(block, &coupling, symbol)?;
        Ok(symbol)
    }
    pub fn decode_step(&mut self, cover: FiniteDistribution, symbol: usize) -> io::Result<()> {
        if self.steps >= MAX_HORIZON {
            return Err(malformed());
        }
        let block = self.next_block();
        let coupling = GreedyCoupling::new(self.posteriors[block].clone(), cover)?;
        self.apply(block, &coupling, symbol)
    }
    pub fn resolved_message(&self) -> io::Result<Vec<usize>> {
        self.posteriors
            .iter()
            .map(|p| p.resolved_symbol().ok_or_else(malformed))
            .collect()
    }
}

/// Agreed finite-state cover law. State changes only with public cover symbols;
/// each fixed record starts at the declared initial state. No model discovery.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConditionalCoverSettings {
    pub initial_state: usize,
    pub state_weights: Vec<Vec<u64>>,
    pub next_states: Vec<Vec<usize>>,
}
impl ConditionalCoverSettings {
    pub fn validate(&self, alphabet: usize) -> io::Result<()> {
        let states = self.state_weights.len();
        if !(1..=16).contains(&states)
            || !(1..=MAX_ALPHABET).contains(&alphabet)
            || self.initial_state >= states
            || self.next_states.len() != states
            || self.state_weights.iter().any(|row| row.len() != alphabet)
            || self
                .next_states
                .iter()
                .any(|row| row.len() != alphabet || row.iter().any(|next| *next >= states))
        {
            return Err(invalid());
        }
        for row in &self.state_weights {
            let cover = FiniteDistribution::new(row.clone())?;
            // Check every state before any entropy or record I/O.
            GreedyCoupling::new(FiniteDistribution::new(vec![1; 256])?, cover)?;
        }
        Ok(())
    }
}

/// Fixed public horizon, memoryless or agreed finite conditional cover codec.
/// Emit the whole returned record; decoding can explicitly fail unresolved.
/// Never retry until resolution, append a resolving suffix, or filter records.
#[derive(Clone, Debug)]
pub struct GeneralCoverByteCodec {
    cover: FiniteDistribution,
    conditional: Option<(ConditionalCoverSettings, Vec<FiniteDistribution>)>,
    message_bytes: usize,
    horizon: usize,
}
impl GeneralCoverByteCodec {
    pub fn new(
        cover: FiniteDistribution,
        message_bytes: usize,
        horizon: usize,
    ) -> io::Result<Self> {
        if !(1..=MAX_BLOCKS).contains(&message_bytes) || !(1..=MAX_HORIZON).contains(&horizon) {
            return Err(invalid());
        }
        // Refuse an initially unsupported rational construction before entropy/I/O.
        GreedyCoupling::new(FiniteDistribution::new(vec![1; 256])?, cover.clone())?;
        Ok(Self {
            cover,
            conditional: None,
            message_bytes,
            horizon,
        })
    }
    pub fn new_conditional(
        model: ConditionalCoverSettings,
        message_bytes: usize,
        horizon: usize,
    ) -> io::Result<Self> {
        let alphabet = model.state_weights.first().map_or(0, Vec::len);
        model.validate(alphabet)?;
        let rows = model
            .state_weights
            .iter()
            .cloned()
            .map(FiniteDistribution::new)
            .collect::<io::Result<Vec<_>>>()?;
        let mut codec = Self::new(rows[model.initial_state].clone(), message_bytes, horizon)?;
        codec.conditional = Some((model, rows));
        Ok(codec)
    }
    fn initial_state(&self) -> usize {
        self.conditional
            .as_ref()
            .map_or(0, |(model, _)| model.initial_state)
    }
    fn conditional_row(&self, state: usize) -> FiniteDistribution {
        self.conditional
            .as_ref()
            .map_or_else(|| self.cover.clone(), |(_, rows)| rows[state].clone())
    }
    fn advance(&self, state: usize, symbol: usize) -> io::Result<usize> {
        match &self.conditional {
            None => Ok(0),
            Some((model, rows)) => {
                if rows[state]
                    .weights()
                    .get(symbol)
                    .is_none_or(|weight| *weight == 0)
                {
                    return Err(malformed());
                }
                Ok(model.next_states[state][symbol])
            }
        }
    }
    pub fn cover(&self) -> &FiniteDistribution {
        &self.cover
    }
    pub fn message_bytes(&self) -> usize {
        self.message_bytes
    }
    pub fn horizon(&self) -> usize {
        self.horizon
    }
    /// Input must be uniformly masked over all bytes, including any AEAD tag.
    /// This function supplies neither masking nor record authentication/freshness.
    pub fn encode<R: RngCore + CryptoRng>(
        &self,
        masked: &[u8],
        rng: &mut R,
    ) -> io::Result<Vec<usize>> {
        if masked.len() != self.message_bytes {
            return Err(invalid());
        }
        let message: Vec<usize> = masked.iter().map(|b| usize::from(*b)).collect();
        let mut state = IterativeCoupling::new(self.message_bytes, 256)?;
        let mut cover_state = self.initial_state();
        (0..self.horizon)
            .map(|_| {
                let symbol = state.encode_step(&message, self.conditional_row(cover_state), rng)?;
                cover_state = self.advance(cover_state, symbol)?;
                Ok(symbol)
            })
            .collect()
    }
    pub fn decode(&self, symbols: &[usize]) -> io::Result<Vec<u8>> {
        if symbols.len() != self.horizon {
            return Err(malformed());
        }
        let mut state = IterativeCoupling::new(self.message_bytes, 256)?;
        let mut cover_state = self.initial_state();
        for symbol in symbols {
            let next = self.advance(cover_state, *symbol)?;
            state.decode_step(self.conditional_row(cover_state), *symbol)?;
            cover_state = next;
        }
        state
            .resolved_message()?
            .into_iter()
            .map(|s| u8::try_from(s).map_err(|_| malformed()))
            .collect()
    }
}

#[cfg(test)]
#[path = "general_coupling_tests.rs"]
mod tests;
