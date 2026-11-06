//! Exact finite rational MEC where the message is a deterministic cover function.
//! Unsupported equal-mass partitions fail; this is not a greedy MEC approximation.
use rand::{CryptoRng, RngCore};
use std::io;

#[derive(Debug, Clone)]
pub struct MinimumEntropyCoupling {
    weights: Vec<u64>,
    group: Vec<usize>,
    mass: u64,
    bits: u8,
}

impl MinimumEntropyCoupling {
    /// Exact cover masses; sum must split into 2^bits equal-mass message bins.
    /// Search is bounded to 100000 nodes, 32 symbols, and 1..=4 bits/symbol.
    pub fn new(weights: Vec<u64>, bits: u8) -> io::Result<Self> {
        let invalid = || {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "unsupported exact deterministic MEC partition",
            )
        };
        if weights.is_empty()
            || weights.len() > 32
            || !(1..=4).contains(&bits)
            || weights.contains(&0)
        {
            return Err(invalid());
        }
        let total = weights
            .iter()
            .try_fold(0_u64, |sum, w| sum.checked_add(*w))
            .ok_or_else(invalid)?;
        let bins = 1_usize << bits;
        if total % bins as u64 != 0 {
            return Err(invalid());
        }
        let mass = total / bins as u64;
        if weights.iter().any(|w| *w > mass) {
            return Err(invalid());
        }
        let mut order: Vec<usize> = (0..weights.len()).collect();
        order.sort_by_key(|i| std::cmp::Reverse(weights[*i]));
        let mut remaining = vec![mass; bins];
        let mut group = vec![0; weights.len()];
        let mut budget = 100_000;
        if !partition(0, &order, &weights, &mut remaining, &mut group, &mut budget) {
            return Err(invalid());
        }
        Ok(Self {
            weights,
            group,
            mass,
            bits,
        })
    }
    pub fn bits_per_symbol(&self) -> u8 {
        self.bits
    }
    pub fn cover_weights(&self) -> &[u64] {
        &self.weights
    }
    /// Exact marginal cover distribution requires uniform independent messages.
    /// Arbitrary plaintext messages do NOT satisfy that assumption.
    pub fn encode<R: RngCore + CryptoRng>(&self, message: usize, rng: &mut R) -> io::Result<usize> {
        if message >= (1 << self.bits) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "message outside coupling alphabet",
            ));
        }
        let mut draw = super::uniform_below(rng, self.mass)?;
        for (symbol, weight) in self.weights.iter().enumerate() {
            if self.group[symbol] == message {
                if draw < *weight {
                    return Ok(symbol);
                }
                draw -= *weight;
            }
        }
        Err(io::Error::other("coupling invariant failed"))
    }
    pub fn decode(&self, symbol: usize) -> io::Result<usize> {
        self.group.get(symbol).copied().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "symbol outside cover alphabet")
        })
    }
    /// Integer joint masses in denominator sum(weights). No floating point proof.
    pub fn joint_weights(&self) -> Vec<Vec<u64>> {
        let mut result = vec![vec![0; self.weights.len()]; 1 << self.bits];
        for (symbol, weight) in self.weights.iter().enumerate() {
            result[self.group[symbol]][symbol] = *weight;
        }
        result
    }
}

fn partition(
    at: usize,
    order: &[usize],
    weights: &[u64],
    remaining: &mut [u64],
    group: &mut [usize],
    budget: &mut usize,
) -> bool {
    if *budget == 0 {
        return false;
    }
    *budget -= 1;
    if at == order.len() {
        return remaining.iter().all(|r| *r == 0);
    }
    let symbol = order[at];
    let mut seen = Vec::new();
    for bin in 0..remaining.len() {
        let available = remaining[bin];
        if available < weights[symbol] || seen.contains(&available) {
            continue;
        }
        seen.push(available);
        remaining[bin] -= weights[symbol];
        group[symbol] = bin;
        if partition(at + 1, order, weights, remaining, group, budget) {
            return true;
        }
        remaining[bin] += weights[symbol];
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{rngs::StdRng, SeedableRng};
    #[test]
    fn exact_marginals_and_global_minimum_argument() {
        let mec = MinimumEntropyCoupling::new(vec![3, 1, 2, 2], 1).unwrap();
        let joint = mec.joint_weights();
        assert_eq!(
            joint
                .iter()
                .map(|r| r.iter().sum::<u64>())
                .collect::<Vec<_>>(),
            vec![4, 4]
        );
        for symbol in 0..4 {
            assert_eq!(
                joint.iter().map(|r| r[symbol]).sum::<u64>(),
                mec.weights[symbol]
            );
        }
        // Each column has one nonzero: H(message | cover)=0, H(joint)=H(cover).
        for symbol in 0..4 {
            assert_eq!(joint.iter().filter(|r| r[symbol] != 0).count(), 1);
        }
        let mut rng = StdRng::seed_from_u64(71);
        for message in 0..2 {
            for _ in 0..100 {
                let cover = mec.encode(message, &mut rng).unwrap();
                assert_eq!(mec.decode(cover).unwrap(), message);
            }
        }
    }
    #[test]
    fn unsupported_not_mislabeled_as_exact_mec() {
        for weights in [vec![9, 1], vec![1, 1, 1], vec![2, 2, 2], vec![0, 2]] {
            assert!(MinimumEntropyCoupling::new(weights, 1).is_err());
        }
        assert!(MinimumEntropyCoupling::new(vec![u64::MAX, 1], 1).is_err());
        let mec = MinimumEntropyCoupling::new(vec![1, 1], 1).unwrap();
        assert!(mec.decode(2).is_err());
    }
}
