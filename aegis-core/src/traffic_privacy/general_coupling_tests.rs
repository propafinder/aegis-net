use super::*;
use rand::{rngs::StdRng, SeedableRng};

fn d(weights: &[u64]) -> FiniteDistribution {
    FiniteDistribution::new(weights.to_vec()).unwrap()
}

#[test]
fn unequal_alphabets_zeros_and_nonpartitionable_cover_have_exact_marginals() {
    let a = d(&[3, 0, 2]);
    let b = d(&[0, 4, 2, 1]);
    let c = GreedyCoupling::new(a.clone(), b.clone()).unwrap();
    assert_eq!(c.denominator(), 35);
    let mut rows = [0; 3];
    let mut columns = [0; 4];
    for cell in c.cells() {
        rows[cell.message] += cell.mass;
        columns[cell.cover] += cell.mass;
    }
    assert_eq!(rows, [21, 0, 14]);
    assert_eq!(columns, [0, 20, 10, 5]);
    c.certify_marginals().unwrap();
    assert!(c.posterior(0).is_err());
    assert!(c.posterior(4).is_err());
    assert!(c.encode(1, &mut StdRng::seed_from_u64(1)).is_err());
}

#[test]
fn largest_residual_greedy_reference_and_ties() {
    let c = GreedyCoupling::new(d(&[5, 3, 2]), d(&[4, 4, 2])).unwrap();
    assert_eq!(
        c.cells(),
        &[
            JointMass {
                message: 0,
                cover: 0,
                mass: 4
            },
            JointMass {
                message: 1,
                cover: 1,
                mass: 3
            },
            JointMass {
                message: 2,
                cover: 2,
                mass: 2
            },
            JointMass {
                message: 0,
                cover: 1,
                mass: 1
            },
        ]
    );
    let c = GreedyCoupling::new(d(&[1, 1]), d(&[1, 1])).unwrap();
    assert_eq!(c.cells()[0].message, 0);
    assert_eq!(c.cells()[0].cover, 0);
}

#[test]
fn canonical_equivalent_rational_models_and_sparse_support_bound() {
    assert_eq!(d(&[12, 0, 6]), d(&[2, 0, 1]));
    for rows in 1..=16 {
        for cols in 1..=17 {
            let c = GreedyCoupling::new(
                d(&(1..=rows).collect::<Vec<_>>()),
                d(&(1..=cols).collect::<Vec<_>>()),
            )
            .unwrap();
            c.certify_marginals().unwrap();
            assert!(c.cells().len() < rows as usize + cols as usize);
        }
    }
}

#[test]
fn invalid_and_overflowing_rationals_refuse_without_rounding() {
    for w in [vec![], vec![0, 0], vec![1; MAX_ALPHABET + 1]] {
        assert!(FiniteDistribution::new(w).is_err());
    }
    assert!(FiniteDistribution::from_masses(vec![u128::MAX, 1]).is_err());
    assert!(FiniteDistribution::from_masses(vec![MAX_MASS, 1]).is_err());
    // Reduction happens before bounds: a mathematically tiny canonical model.
    assert_eq!(
        FiniteDistribution::from_masses(vec![u128::MAX, u128::MAX]).unwrap(),
        d(&[1, 1])
    );
    let a = FiniteDistribution::from_masses(vec![MAX_MASS - 1, 1]).unwrap();
    let b = FiniteDistribution::from_masses(vec![MAX_MASS - 2, 1]).unwrap();
    assert!(GreedyCoupling::new(a, b).is_err());
    assert!(IterativeCoupling::new(0, 2).is_err());
    assert!(IterativeCoupling::new(1, MAX_ALPHABET + 1).is_err());
    assert!(GeneralCoverByteCodec::new(d(&[1, 1]), MAX_BLOCKS + 1, 1).is_err());
    assert!(GeneralCoverByteCodec::new(d(&[1, 1]), 1, MAX_HORIZON + 1).is_err());
}

#[test]
fn integer_entropy_has_known_values_and_peer_stable_order() {
    assert_eq!(d(&[1]).entropy_score_q32(), 0);
    assert_eq!(d(&[1, 1]).entropy_score_q32(), 1 << 32);
    assert_eq!(d(&[1; 256]).entropy_score_q32(), 8 << 32);
    assert!(d(&[1, 1]).entropy_score_q32() > d(&[99, 1]).entropy_score_q32());
    let mut state = IterativeCoupling::new(2, 2).unwrap();
    assert_eq!(state.next_block(), 0);
    state.decode_step(d(&[1, 1]), 1).unwrap();
    assert_eq!(state.next_block(), 1);
    state.decode_step(d(&[1, 1]), 0).unwrap();
    assert_eq!(state.resolved_message().unwrap(), [1, 0]);
    assert_eq!(state.next_block(), 0); // public padding, not early stopping
}

#[test]
fn multi_block_encoder_and_decoder_follow_identical_posteriors() {
    let mut rng = StdRng::seed_from_u64(391);
    let mut encoder = IterativeCoupling::new(3, 16).unwrap();
    let mut decoder = IterativeCoupling::new(3, 16).unwrap();
    let message = [2, 15, 8];
    for step in 0..128 {
        // Shared conditional models can have different alphabets and zeros.
        let cover = if step % 2 == 0 {
            d(&[4, 2, 1])
        } else {
            d(&[1, 0, 3, 2])
        };
        assert_eq!(encoder.next_block(), decoder.next_block());
        let symbol = encoder
            .encode_step(&message, cover.clone(), &mut rng)
            .unwrap();
        decoder.decode_step(cover, symbol).unwrap();
        assert_eq!(encoder.posteriors(), decoder.posteriors());
    }
    assert_eq!(decoder.resolved_message().unwrap(), message);
}

#[test]
fn all_byte_values_roundtrip_on_arbitrary_non_partition_cover() {
    // Total7 cannot split into the old deterministic equal-mass bit bins.
    let codec = GeneralCoverByteCodec::new(d(&[4, 2, 1]), 1, 128).unwrap();
    let mut rng = StdRng::seed_from_u64(17);
    for byte in 0..=255 {
        let symbols = codec.encode(&[byte], &mut rng).unwrap();
        assert_eq!(symbols.len(), 128);
        assert_eq!(codec.decode(&symbols).unwrap(), [byte]);
    }
}

#[test]
fn multi_byte_record_keeps_full_public_horizon_after_resolution() {
    let codec = GeneralCoverByteCodec::new(d(&[1; 256]), 4, 17).unwrap();
    let symbols = codec
        .encode(&[0, 255, 37, 128], &mut StdRng::seed_from_u64(7))
        .unwrap();
    assert_eq!(symbols.len(), 17);
    assert_eq!(codec.decode(&symbols).unwrap(), [0, 255, 37, 128]);
    assert!(codec.decode(&symbols[..16]).is_err());
    assert!(codec
        .encode(&[0, 255, 37], &mut StdRng::seed_from_u64(7))
        .is_err());
}

#[test]
fn insufficient_or_no_information_cover_refuses_without_guessing() {
    let codec = GeneralCoverByteCodec::new(d(&[1]), 1, 128).unwrap();
    let symbols = codec.encode(&[91], &mut StdRng::seed_from_u64(7)).unwrap();
    assert_eq!(symbols, vec![0; 128]);
    assert!(codec.decode(&symbols).is_err());
    let codec = GeneralCoverByteCodec::new(d(&[1, 1]), 2, 1).unwrap();
    let symbols = codec
        .encode(&[0, 255], &mut StdRng::seed_from_u64(8))
        .unwrap();
    assert!(codec.decode(&symbols).is_err());
}

#[test]
fn out_of_alphabet_zero_mass_and_corrupted_length_refuse() {
    let codec = GeneralCoverByteCodec::new(d(&[1, 0, 1]), 1, 16).unwrap();
    let mut symbols = codec.encode(&[17], &mut StdRng::seed_from_u64(2)).unwrap();
    symbols[0] = 1;
    assert!(codec.decode(&symbols).is_err());
    symbols[0] = 3;
    assert!(codec.decode(&symbols).is_err());
    symbols.push(0);
    assert!(codec.decode(&symbols).is_err());
    let mut state = IterativeCoupling::new(1, 2).unwrap();
    assert!(state
        .encode_step(&[2], d(&[1, 1]), &mut StdRng::seed_from_u64(1))
        .is_err());
    assert!(state
        .encode_step(&[], d(&[1, 1]), &mut StdRng::seed_from_u64(1))
        .is_err());
}

#[test]
fn hard_public_horizon_refuses_additional_sender_and_receiver_steps() {
    let mut sender = IterativeCoupling::new(1, 1).unwrap();
    let mut receiver = IterativeCoupling::new(1, 1).unwrap();
    let mut rng = StdRng::seed_from_u64(12);
    for _ in 0..MAX_HORIZON {
        sender.encode_step(&[0], d(&[1]), &mut rng).unwrap();
        receiver.decode_step(d(&[1]), 0).unwrap();
    }
    assert!(sender.encode_step(&[0], d(&[1]), &mut rng).is_err());
    assert!(receiver.decode_step(d(&[1]), 0).is_err());
}

struct FailedEntropy;
impl RngCore for FailedEntropy {
    fn next_u32(&mut self) -> u32 {
        panic!("infallible RNG prohibited")
    }
    fn next_u64(&mut self) -> u64 {
        panic!("infallible RNG prohibited")
    }
    fn fill_bytes(&mut self, _: &mut [u8]) {
        panic!("infallible RNG prohibited")
    }
    fn try_fill_bytes(&mut self, _: &mut [u8]) -> Result<(), rand::Error> {
        Err(rand::Error::new(io::Error::other(
            "controlled entropy failure",
        )))
    }
}
impl CryptoRng for FailedEntropy {}

struct ControlledDraws {
    calls: usize,
    second: u128,
}
impl RngCore for ControlledDraws {
    fn next_u32(&mut self) -> u32 {
        panic!("infallible RNG prohibited")
    }
    fn next_u64(&mut self) -> u64 {
        panic!("infallible RNG prohibited")
    }
    fn fill_bytes(&mut self, _: &mut [u8]) {
        panic!("infallible RNG prohibited")
    }
    fn try_fill_bytes(&mut self, out: &mut [u8]) -> Result<(), rand::Error> {
        assert_eq!(out.len(), 16);
        self.calls += 1;
        let value = if self.calls == 1 { 0 } else { self.second };
        out.copy_from_slice(&value.to_le_bytes());
        Ok(())
    }
}
impl CryptoRng for ControlledDraws {}

#[test]
fn exact_rejection_sampler_rejects_low_prefix_without_modulo_fallback() {
    let c = GreedyCoupling::new(d(&[1]), d(&[2, 1])).unwrap();
    let mut draws = ControlledDraws {
        calls: 0,
        second: 2,
    };
    // upper=3, threshold=1: zero must be rejected, 2 selects the second column.
    assert_eq!(c.encode(0, &mut draws).unwrap(), 1);
    assert_eq!(draws.calls, 2);
}

#[test]
fn hostile_entropy_exhaustion_is_finite_and_posterior_stays_unadvanced() {
    let mut state = IterativeCoupling::new(1, 1).unwrap();
    let mut draws = ControlledDraws {
        calls: 0,
        second: 0,
    };
    let before = state.posteriors().to_vec();
    assert!(state.encode_step(&[0], d(&[2, 1]), &mut draws).is_err());
    assert_eq!(draws.calls, 128);
    assert_eq!(state.posteriors(), before);
    assert_eq!(state.steps, 0);
}

#[test]
fn failed_entropy_does_not_advance_the_posterior_or_fallback() {
    let mut state = IterativeCoupling::new(1, 2).unwrap();
    let before = state.posteriors().to_vec();
    assert!(state
        .encode_step(&[0], d(&[2, 1]), &mut FailedEntropy)
        .is_err());
    assert_eq!(state.posteriors(), before);
    assert_eq!(state.steps, 0);
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Fraction(u128, u128);
impl Fraction {
    fn new(n: u128, d: u128) -> Self {
        let g = gcd(n, d);
        Self(n / g, d / g)
    }
    fn mul(self, other: Self) -> Self {
        Self::new(self.0 * other.0, self.1 * other.1)
    }
    fn add(self, other: Self) -> Self {
        Self::new(self.0 * other.1 + other.0 * self.1, self.1 * other.1)
    }
}

#[test]
fn exhaustive_multiblock_two_step_transcript_marginal_is_cover_product() {
    let cover = d(&[3, 2]);
    let mut transcript_probabilities = [Fraction(0, 1); 4];
    for a in 0..2 {
        for b in 0..2 {
            let message = [a, b];
            let initial = IterativeCoupling::new(2, 2).unwrap();
            let first = GreedyCoupling::new(initial.posteriors[0].clone(), cover.clone()).unwrap();
            for cell in first.cells().iter().filter(|c| c.message == a) {
                let p = Fraction::new(cell.mass, first.denominator / 2);
                let mut decoded = IterativeCoupling::new(2, 2).unwrap();
                decoded.decode_step(cover.clone(), cell.cover).unwrap();
                let block = decoded.next_block();
                let second =
                    GreedyCoupling::new(decoded.posteriors[block].clone(), cover.clone()).unwrap();
                let row_mass = decoded.posteriors[block].weights[message[block]]
                    * (second.denominator / decoded.posteriors[block].total);
                for next in second
                    .cells()
                    .iter()
                    .filter(|c| c.message == message[block])
                {
                    let path = cell.cover * 2 + next.cover;
                    let value = Fraction::new(1, 4)
                        .mul(p)
                        .mul(Fraction::new(next.mass, row_mass));
                    transcript_probabilities[path] = transcript_probabilities[path].add(value);
                }
            }
        }
    }
    assert_eq!(
        transcript_probabilities,
        [
            Fraction::new(9, 25),
            Fraction::new(6, 25),
            Fraction::new(6, 25),
            Fraction::new(4, 25)
        ]
    );
}

#[test]
fn exact_posterior_column_masses_not_map_guesses() {
    let c = GreedyCoupling::new(d(&[1, 1]), d(&[3, 2])).unwrap();
    assert_eq!(c.posterior(0).unwrap(), d(&[5, 1]));
    assert_eq!(c.posterior(1).unwrap(), d(&[0, 1]));
    assert_eq!(c.posterior(0).unwrap().resolved_symbol(), None);
}
#[test]
fn conditional_cover_uses_agreed_public_prefix_and_rejects_bad_state() {
    use super::ConditionalCoverSettings;
    let model = ConditionalCoverSettings {
        initial_state: 0,
        state_weights: vec![vec![1, 1], vec![3, 1]],
        next_states: vec![vec![0, 1], vec![0, 1]],
    };
    model.validate(2).unwrap();
    let codec = GeneralCoverByteCodec::new_conditional(model.clone(), 1, 64).unwrap();
    let mut rng = rand::rngs::StdRng::seed_from_u64(17);
    let symbols = codec.encode(&[193], &mut rng).unwrap();
    assert_eq!(codec.decode(&symbols).unwrap(), vec![193]);
    let mut invalid = model;
    invalid.next_states[1][0] = 2;
    assert!(GeneralCoverByteCodec::new_conditional(invalid, 1, 64).is_err());
}

#[test]
fn conditional_byte_codec_exact_prefix_law_and_record_reset() {
    // Enumerate the whole uniform byte message alphabet, rather than estimate
    // the prefix law from Monte Carlo samples. First token is the byte; the
    // public prefix then selects one of two deterministic conditional rows.
    let mut zero = vec![0; 256];
    zero[0] = 1;
    let mut last = vec![0; 256];
    last[255] = 1;
    let model = ConditionalCoverSettings {
        initial_state: 0,
        state_weights: vec![vec![1; 256], zero, last],
        next_states: vec![
            (0..256).map(|symbol| 1 + symbol % 2).collect(),
            vec![1; 256],
            vec![2; 256],
        ],
    };
    let codec = GeneralCoverByteCodec::new_conditional(model, 1, 4).unwrap();
    let mut counts = vec![0; 256];
    let mut rng = StdRng::seed_from_u64(617);
    for byte in 0..=255u8 {
        let tokens = codec.encode(&[byte], &mut rng).unwrap();
        let continuation = if byte % 2 == 0 { 0 } else { 255 };
        assert_eq!(
            tokens,
            vec![usize::from(byte), continuation, continuation, continuation]
        );
        counts[tokens[0]] += 1;
        assert_eq!(codec.decode(&tokens).unwrap(), [byte]);
        let mut impossible = tokens;
        impossible[1] = 1;
        assert!(codec.decode(&impossible).is_err());
    }
    assert_eq!(counts, vec![1; 256]);
}

#[test]
fn conditional_tables_are_finite_closed_and_validated_before_use() {
    let valid = ConditionalCoverSettings {
        initial_state: 1,
        state_weights: vec![vec![1, 0], vec![1, 1]],
        // State zero is unreachable, but its row and transitions must validate.
        next_states: vec![vec![0, 1], vec![1, 1]],
    };
    for variant in 0..6 {
        let mut model = valid.clone();
        match variant {
            0 => model.initial_state = 2,
            1 => model.state_weights[0] = vec![0, 0],
            2 => model.state_weights[0].pop().map(|_| ()).unwrap(),
            3 => model.next_states[0].pop().map(|_| ()).unwrap(),
            4 => model.next_states[0][0] = 2,
            5 => {
                model.state_weights = vec![vec![1, 1]; 17];
                model.next_states = vec![vec![0, 0]; 17];
            }
            _ => unreachable!(),
        }
        assert!(
            GeneralCoverByteCodec::new_conditional(model, 1, 64).is_err(),
            "variant {variant}"
        );
    }
    let codec = GeneralCoverByteCodec::new_conditional(valid, 1, 64).unwrap();
    assert!(codec.decode(&vec![2; 64]).is_err());
}

#[test]
fn conditional_no_information_keeps_horizon_and_refuses_unresolved_message() {
    let model = ConditionalCoverSettings {
        initial_state: 0,
        state_weights: vec![vec![1, 0], vec![0, 1]],
        next_states: vec![vec![1, 1], vec![0, 0]],
    };
    let codec = GeneralCoverByteCodec::new_conditional(model, 1, 16).unwrap();
    let symbols = codec.encode(&[37], &mut StdRng::seed_from_u64(94)).unwrap();
    assert_eq!(symbols, (0..16).map(|step| step % 2).collect::<Vec<_>>());
    assert!(codec.decode(&symbols).is_err());
}
