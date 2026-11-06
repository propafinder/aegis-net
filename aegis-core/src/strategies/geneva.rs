//! Run an evolved Geneva strategy against live traffic.
//!
//! `aegis-geneva` evolves strategies offline against censor models and is
//! deliberately I/O-free. This is the bridge that executes one on the wire.
//!
//! The genuine TCP connection belongs to the kernel — we do not own its
//! sequence/ack state — so a Geneva action tree cannot be used to rewrite the
//! real segments. What it *can* do, and what actually defeats a middlebox, is
//! decide the **decoy plan**: which extra packets to put on the wire around the
//! real write. The live bridge accepts pass/duplicate, bounded TTL replacement,
//! and payload tampering only inside a TTL-bounded decoy branch whose expiry is
//! proven from a live path observation. The full Geneva grammar remains
//! available to the offline engine; unsupported live actions fail at startup.
//!
//! Every accepted live program must keep one unchanged pass branch. That branch
//! is represented by the kernel write; the remaining bounded TTL/duplicate
//! branches are emitted as raw decoys.

use super::{SendFirstContext, Strategy, StrategyRequirements};
use crate::raw_engine::{default_raw_engine, RawEngine};
use aegis_geneva::engine::apply::run as geneva_run;
use aegis_geneva::packet::field::{Field, Proto};
use aegis_geneva::packet::model::{tcp_flags, Direction, IpHeader, Packet};
use aegis_geneva::syntax::action::{Action, TamperMode};
use aegis_geneva::Strategy as GenevaProgram;
use async_trait::async_trait;
use rand::{rngs::StdRng, Rng, SeedableRng};
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tracing::trace;

/// Hard live limit on decoys for one write. Programs above it are rejected;
/// silently truncating an evolved action tree would execute a different plan.
const MAX_DECOYS_PER_WRITE: usize = 8;

/// The strategy configured for this process, parsed once at startup.
///
/// The planner instantiates strategies by id and does not carry the config, so
/// the compiled program is published here — the same shape the forensic-safe
/// flag uses. `None` means `direct.geneva_strategy` was not set, in which case
/// the `geneva` id simply yields no strategy and the planner moves on.
static CONFIGURED: std::sync::OnceLock<Option<GenevaProgram>> = std::sync::OnceLock::new();

/// Parse and publish the process-wide Geneva strategy. Returns the parse error
/// so startup can fail loudly on a malformed program instead of quietly running
/// without the evasion the operator asked for.
pub fn configure(dsl: Option<&str>) -> aegis_geneva::Result<()> {
    let program = match dsl {
        Some(text) if !text.trim().is_empty() => Some(GenevaStrategy::from_dsl(text)?.program),
        _ => None,
    };
    // A second configure with different DSL text must not be swallowed. The
    // strategy is published once and read by every later connection, so
    // silently keeping the first program while startup reports success would
    // put a different evasion on the wire than the config asks for.
    if let Err(rejected) = CONFIGURED.set(program) {
        // Idempotent re-configuration with the same program is fine; a
        // DIFFERENT one is not. OnceLock would keep the first, so startup
        // would report success while the wire ran a program the operator did
        // not ask for.
        if CONFIGURED.get() != Some(&rejected) {
            return Err(aegis_geneva::Error::Syntax(
                "geneva strategy already configured with a different program; the first one \
                 stays on the wire, so this configure() would silently do nothing"
                    .to_string(),
            ));
        }
    }
    Ok(())
}

/// The configured strategy, if any. `seed` varies the decoy set per session.
pub fn configured_strategy(seed: u64) -> Option<GenevaStrategy> {
    CONFIGURED.get()?.as_ref().map(|program| GenevaStrategy {
        program: program.clone(),
        engine: default_raw_engine(),
        seed,
    })
}

pub struct GenevaStrategy {
    program: GenevaProgram,
    engine: Arc<dyn RawEngine>,
    /// Per-session seed retained for deterministic projection of payload
    /// corrupt/replace actions and the bounded live decoy set.
    seed: u64,
}

/// Reject Geneva syntax that the live raw bridge cannot preserve exactly.
/// Offline evolution keeps the full grammar; production startup is narrower
/// until those fields have a wire serializer rather than silently mapping an
/// unrelated action to a TTL packet.
fn validate_live_program(program: &GenevaProgram) -> aegis_geneva::Result<()> {
    fn validate_action(action: &Action, decoy_ttl: Option<u8>) -> aegis_geneva::Result<()> {
        match action {
            Action::Pass | Action::Drop => Ok(()),
            Action::Duplicate { left, right } => {
                validate_action(left, decoy_ttl)?;
                validate_action(right, decoy_ttl)
            }
            Action::Fragment {
                proto,
                offset,
                left,
                right,
                ..
            } => {
                if *proto != Proto::Tcp {
                    return Err(aegis_geneva::Error::Syntax(
                        "live Geneva currently serializes TCP fragmentation exactly; IP fragment trees must use the dedicated ip_frag strategy"
                            .into(),
                    ));
                }
                if decoy_ttl.is_none() || *offset == 0 {
                    return Err(aegis_geneva::Error::Syntax(
                        "live Geneva TCP fragmentation requires a nonzero offset inside a bounded IP ttl replace decoy branch"
                            .into(),
                    ));
                }
                validate_action(left, decoy_ttl)?;
                validate_action(right, decoy_ttl)
            }
            Action::Tamper { field, mode, next } => {
                let Some(ttl) = (match (field, mode) {
                    (Field::Ttl, TamperMode::Replace(value)) if (1..=64).contains(value) => {
                        Some(*value as u8)
                    }
                    _ => None,
                }) else {
                    return Err(aegis_geneva::Error::Syntax(format!(
                        "live Geneva supports only IP ttl replace values 1..=64 exactly; rejected {field}"
                    )));
                };
                validate_action(next, Some(ttl))
            }
            Action::TamperPayload { next, .. } => {
                if decoy_ttl.is_none() {
                    return Err(aegis_geneva::Error::Syntax(
                        "live Geneva payload tamper requires an enclosing bounded IP ttl replace branch"
                            .into(),
                    ));
                }
                validate_action(next, decoy_ttl)
            }
        }
    }

    if !program.inbound.is_empty() {
        return Err(aegis_geneva::Error::Syntax(
            "live Geneva bridge shapes the first outbound payload only; inbound rules are unsupported"
                .into(),
        ));
    }
    for rule in &program.outbound {
        validate_action(&rule.action, None)?;
    }
    let canonical = GenevaStrategy::model_packet(&[]);
    if program.first_match(&canonical).is_none() {
        return Err(aegis_geneva::Error::Syntax(
            "live Geneva program has no rule matching the first outbound PSH-ACK payload".into(),
        ));
    }
    let mut validation_rng = StdRng::seed_from_u64(0);
    project_decoys(program, &canonical, &mut validation_rng).map_err(|error| {
        aegis_geneva::Error::Syntax(format!(
            "live Geneva program has no executable decoy effect: {error}"
        ))
    })?;
    Ok(())
}

impl GenevaStrategy {
    /// Parse a strategy from its Geneva DSL text, e.g.
    /// `[TCP:flags:PA]-duplicate(tamper{IP:ttl:replace:4}(),)-| \/`.
    pub fn from_dsl(text: &str) -> aegis_geneva::Result<Self> {
        let program = GenevaProgram::parse(text)?;
        // A strategy with no rules is the identity — legitimate inside the GA as
        // the baseline to beat, but as operator configuration it means "Geneva is
        // on and doing nothing". Silently applying no evasion while the operator
        // believes otherwise is the worst outcome for this feature, so refuse it
        // here rather than in the crate (the trainer still needs identity).
        if program.outbound.is_empty() && program.inbound.is_empty() {
            return Err(aegis_geneva::Error::Syntax(format!(
                "geneva strategy has no rules (parsed as identity, which would apply no evasion): {text:?}"
            )));
        }
        validate_live_program(&program)?;
        Ok(Self {
            program,
            engine: default_raw_engine(),
            seed: 0,
        })
    }

    pub fn with_seed(mut self, seed: u64) -> Self {
        self.seed = seed;
        self
    }

    /// The outbound packet the strategy is asked to transform: the first data
    /// segment of this connection as the censor would see it.
    fn model_packet(data: &[u8]) -> Packet {
        Packet {
            wire_fields: Default::default(),
            ip: IpHeader::default(),
            tcp: Some(aegis_geneva::packet::model::TcpHeader {
                flags: tcp_flags::PSH | tcp_flags::ACK,
                seq: 1,
                ack: 1,
                window: 65535,
                checksum: 0,
                data_offset: 5,
            }),
            payload: data.to_vec(),
            direction: Direction::Outbound,
        }
    }

    fn validated_decoy_plan(
        &self,
        data: &[u8],
        ctx: &SendFirstContext,
    ) -> std::io::Result<(Packet, Vec<Packet>)> {
        let original = Self::model_packet(data);
        let mut rng = StdRng::seed_from_u64(self.seed ^ (ctx.dst.port() as u64));
        let emitted = project_decoys(&self.program, &original, &mut rng)?;
        validate_payload_decoy_runtime_safety(&original, &emitted, ctx.reference_path_hops)?;
        Ok((original, emitted))
    }
}

/// Project a Geneva action onto the additional raw packets AEGIS must emit.
///
/// The kernel socket sends the real first segment exactly once after this
/// plan. Geneva's pure engine includes that real/pass branch in its output, so
/// forwarding every emitted model as raw traffic duplicated the real packet:
/// `duplicate(tamper, pass)` became two raw packets plus the kernel packet.
/// Worse, an unmatched rule returns the original unchanged, which the old
/// bridge misreported as a Geneva decoy even though the trigger never fired.
fn project_decoys<R: Rng + ?Sized>(
    program: &GenevaProgram,
    original: &Packet,
    rng: &mut R,
) -> std::io::Result<Vec<Packet>> {
    if program.first_match(original).is_none() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "geneva program did not match the first outbound payload packet",
        ));
    }

    let mut emitted = geneva_run(program, vec![original.clone()], rng);
    if emitted.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "geneva program emitted no packet effect",
        ));
    }

    // Exactly one unchanged branch is represented by the canonical kernel
    // write below. Any additional identical branch is a deliberate duplicate
    // and remains in the decoy plan.
    let Some(real_branch) = emitted.iter().position(|packet| packet == original) else {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "geneva program must retain one unchanged pass branch for the canonical kernel write",
        ));
    };
    emitted.remove(real_branch);
    if emitted.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "geneva program matched but produced no decoy effect",
        ));
    }
    if emitted.len() > MAX_DECOYS_PER_WRITE {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "geneva program emits {} decoys; live maximum is {}",
                emitted.len(),
                MAX_DECOYS_PER_WRITE
            ),
        ));
    }
    Ok(emitted)
}

fn validate_payload_decoy_runtime_safety(
    original: &Packet,
    decoys: &[Packet],
    reference_path_hops: Option<u8>,
) -> std::io::Result<()> {
    for packet in decoys {
        if packet.payload.is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "geneva TCP fragmentation produced an empty live decoy segment",
            ));
        }
        if packet.payload == original.payload {
            continue;
        }
        let hops = reference_path_hops.ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "geneva payload-tampered decoy requires an observed destination hop count",
            )
        })?;
        if packet.ip.ttl >= hops {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "geneva payload-tampered decoy TTL {} is not below observed destination distance {}",
                    packet.ip.ttl, hops
                ),
            ));
        }
    }
    Ok(())
}

#[async_trait]
impl Strategy for GenevaStrategy {
    fn id(&self) -> &'static str {
        "geneva"
    }

    fn requirements(&self) -> StrategyRequirements {
        // Every primitive this maps onto needs raw IPv4 plus the exact kernel
        // sequence numbers, exactly like ttl_desync/ip_frag. Without them the
        // planner filters this strategy out rather than silently degrading.
        StrategyRequirements {
            needs_raw_ipv4: true,
            needs_exact_tcp_seq: true,
            ipv4_only: true,
        }
    }

    fn preflight_send_first(
        &self,
        data: &[u8],
        _sni: Option<(usize, usize)>,
        ctx: &SendFirstContext,
    ) -> std::io::Result<()> {
        self.validated_decoy_plan(data, ctx).map(|_| ())
    }

    async fn send_first(
        &self,
        stream: &mut TcpStream,
        data: &[u8],
        _sni: Option<(usize, usize)>,
        ctx: &SendFirstContext,
    ) -> std::io::Result<()> {
        let (original, emitted) = self.validated_decoy_plan(data, ctx)?;
        let baseline_ttl = original.ip.ttl;

        trace!(
            strategy_id = self.id(),
            emitted = emitted.len(),
            "geneva plan produced"
        );

        for packet in emitted {
            // Preserve the projected Geneva payload byte-for-byte. In
            // particular, an intentional truncate-to-zero must not silently
            // turn back into the canonical user payload.
            let payload = packet.payload.as_slice();
            // Validation limits live programs to actions this raw serializer
            // can reproduce exactly and proves altered payloads expire before
            // the server.
            let sequence_offset = packet
                .tcp
                .as_ref()
                .and_then(|tcp| {
                    original
                        .tcp
                        .as_ref()
                        .map(|base| tcp.seq.wrapping_sub(base.seq))
                })
                .unwrap_or(0);
            if sequence_offset == 0 {
                self.engine.try_send_ttl_desync_first_packet(
                    stream,
                    ctx.dst,
                    payload,
                    packet.ip.ttl.min(baseline_ttl),
                    None,
                    self.id(),
                )?;
            } else {
                self.engine.try_send_ttl_desync_first_packet_at_seq_offset(
                    stream,
                    ctx.dst,
                    payload,
                    packet.ip.ttl.min(baseline_ttl),
                    sequence_offset,
                    self.id(),
                )?;
            }
        }

        // The real data always goes out through the kernel socket: the decoys
        // above are for the middlebox, the connection is for the user.
        stream.write_all(data).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checksum_tamper_is_rejected_until_it_has_an_exact_live_serializer() {
        for unsupported in [
            r"[TCP:flags:PA]-duplicate(tamper{TCP:chksum:replace:0}(),)-| \/",
            r"[TCP:flags:PA]-duplicate(tamper{IP:chksum:replace:1234}(),)-| \/",
        ] {
            assert!(GenevaStrategy::from_dsl(unsupported).is_err());
        }
    }

    #[test]
    fn parses_a_geneva_dsl_strategy() {
        let s = GenevaStrategy::from_dsl(r"[TCP:flags:PA]-duplicate(,)-| \/");
        assert!(s.is_ok(), "{:?}", s.err());
    }

    #[test]
    fn rejects_malformed_dsl_instead_of_panicking() {
        assert!(GenevaStrategy::from_dsl("this is not a strategy").is_err());
        assert!(GenevaStrategy::from_dsl("").is_err());
    }

    #[test]
    fn rejects_live_programs_the_bridge_cannot_execute_exactly() {
        for unsupported in [
            r"[TCP:flags:S]-duplicate(tamper{IP:ttl:replace:4}(),)-| \/",
            r"[TCP:flags:PA]-tamper{TCP:window:replace:1}()-| \/",
            r"[TCP:flags:PA]-duplicate(tamper{TCP:flags:replace:RA}(),)-| \/",
            r"[TCP:flags:PA]-fragment{IP:4:in-order}(,)-| \/",
            r"[TCP:flags:PA]-fragment{TCP:4:in-order}(,)-| \/",
            r"[TCP:flags:PA]-duplicate(tamper{IP:ttl:corrupt}(),)-| \/",
            r"[TCP:flags:PA]-duplicate(tamper{IP:ttl:replace:65}(),)-| \/",
            r"[TCP:flags:PA]-duplicate(tamper{TCP:load:corrupt}(),)-| \/",
            r"[TCP:flags:PA]-drop-| \/",
            r"\/ [TCP:flags:A]-drop-|",
        ] {
            assert!(
                GenevaStrategy::from_dsl(unsupported).is_err(),
                "unsupported live program was accepted: {unsupported}"
            );
        }
    }

    // The DSL we ship in config.example.toml must actually parse, or the first
    // thing an operator copies out of the docs fails at startup.
    #[test]
    fn documented_example_strategy_parses() {
        let documented = r"[TCP:flags:PA]-duplicate(tamper{IP:ttl:replace:4}(),)-| \/";
        let example = include_str!("../../../config.example.toml");
        assert!(
            example.contains(documented),
            "config.example.toml no longer documents this DSL; keep the test and the example in step"
        );
        assert!(GenevaStrategy::from_dsl(documented).is_ok());
    }

    #[test]
    fn requirements_match_the_raw_primitives_it_uses() {
        let s = GenevaStrategy::from_dsl(r"[TCP:flags:PA]-duplicate(,)-| \/").unwrap();
        let r = s.requirements();
        assert!(r.needs_raw_ipv4 && r.needs_exact_tcp_seq && r.ipv4_only);
        assert_eq!(s.id(), "geneva");
    }

    // A drop-everything strategy has no decoy effect and must fail honestly;
    // the direct planner may then try another strategy instead of reporting a
    // Geneva success whose only traffic was the canonical kernel write.
    #[test]
    fn drop_strategy_yields_no_decoys() {
        let program = GenevaProgram::parse(r"[TCP:flags:PA]-drop-| \/").unwrap();
        let mut rng = StdRng::seed_from_u64(0);
        let original = GenevaStrategy::model_packet(b"hello");
        assert!(project_decoys(&program, &original, &mut rng).is_err());
    }

    #[test]
    fn live_program_requires_a_canonical_real_branch() {
        assert!(
            GenevaStrategy::from_dsl(r"[TCP:flags:PA]-tamper{IP:ttl:replace:4}()-| \/").is_err()
        );
    }

    #[test]
    fn unmatched_trigger_is_not_misreported_as_a_decoy() {
        // The full pure engine keeps arbitrary programs for offline
        // evolution. The live constructor rejects this one at startup.
        let program =
            GenevaProgram::parse(r"[TCP:flags:S]-duplicate(tamper{IP:ttl:replace:4}(),)-| \/")
                .unwrap();
        let mut rng = StdRng::seed_from_u64(0);
        let original = GenevaStrategy::model_packet(b"hello");
        let error = project_decoys(&program, &original, &mut rng).expect_err("SYN cannot match PA");
        assert!(error.to_string().contains("did not match"));
    }

    #[test]
    fn duplicate_ttl_program_projects_only_the_tampered_branch() {
        let program =
            GenevaProgram::parse(r"[TCP:flags:PA]-duplicate(tamper{IP:ttl:replace:4}(),)-| \/")
                .unwrap();
        let mut rng = StdRng::seed_from_u64(0);
        let original = GenevaStrategy::model_packet(b"hello");
        let decoys = project_decoys(&program, &original, &mut rng).expect("decoy plan");
        assert_eq!(decoys.len(), 1, "the unchanged branch is the kernel write");
        assert_eq!(decoys[0].ip.ttl, 4);
        assert_eq!(decoys[0].payload, original.payload);
        validate_payload_decoy_runtime_safety(&original, &decoys, None)
            .expect("an unchanged TTL decoy cannot corrupt the server stream");
    }

    #[test]
    fn payload_tamper_is_live_only_inside_a_proven_expiring_ttl_branch() {
        let dsl =
            r"[TCP:flags:PA]-duplicate(tamper{IP:ttl:replace:5}(tamper{TCP:load:corrupt}()),)-| \/";
        let strategy = GenevaStrategy::from_dsl(dsl).expect("safe live payload decoy syntax");
        let original = GenevaStrategy::model_packet(b"GET /secret HTTP/1.1");
        let mut rng = StdRng::seed_from_u64(0);
        let decoys = project_decoys(&strategy.program, &original, &mut rng).expect("decoy plan");
        assert_eq!(decoys.len(), 1);
        assert_eq!(decoys[0].ip.ttl, 5);
        assert_ne!(decoys[0].payload, original.payload);

        let missing = validate_payload_decoy_runtime_safety(&original, &decoys, None)
            .expect_err("an unobserved path cannot prove decoy expiry");
        assert!(missing
            .to_string()
            .contains("observed destination hop count"));
        let too_close = validate_payload_decoy_runtime_safety(&original, &decoys, Some(5))
            .expect_err("TTL equal to the path distance is not a safety margin");
        assert!(too_close.to_string().contains("not below"));
        validate_payload_decoy_runtime_safety(&original, &decoys, Some(10))
            .expect("TTL 5 expires before an observed 10-hop server");

        let missing_context = SendFirstContext {
            dst: "203.0.113.10:443".parse().expect("test destination"),
            reference_path_hops: None,
        };
        assert!(strategy
            .preflight_send_first(b"GET /secret HTTP/1.1", None, &missing_context)
            .expect_err("preflight must reject an unproven payload decoy")
            .to_string()
            .contains("observed destination hop count"));
        let observed_context = SendFirstContext {
            reference_path_hops: Some(10),
            ..missing_context
        };
        strategy
            .preflight_send_first(b"GET /secret HTTP/1.1", None, &observed_context)
            .expect("preflight accepts a decoy proven to expire before the destination");
    }

    #[test]
    fn bounded_tcp_fragment_tree_projects_exact_sequence_offsets_and_order() {
        for (order, expected_payloads, expected_offsets) in [
            (
                "in-order",
                vec![b"abc".as_slice(), b"defgh".as_slice()],
                vec![0, 3],
            ),
            (
                "reversed",
                vec![b"defgh".as_slice(), b"abc".as_slice()],
                vec![3, 0],
            ),
        ] {
            let dsl = format!(
                "[TCP:flags:PA]-duplicate(tamper{{IP:ttl:replace:4}}(fragment{{TCP:3:{order}}}(,)),)-| \\/"
            );
            let strategy = GenevaStrategy::from_dsl(&dsl).expect("bounded TCP fragment plan");
            let original = GenevaStrategy::model_packet(b"abcdefgh");
            let mut rng = StdRng::seed_from_u64(0);
            let decoys =
                project_decoys(&strategy.program, &original, &mut rng).expect("decoy projection");
            assert_eq!(
                decoys
                    .iter()
                    .map(|packet| packet.payload.as_slice())
                    .collect::<Vec<_>>(),
                expected_payloads
            );
            assert_eq!(
                decoys
                    .iter()
                    .map(|packet| packet.tcp.as_ref().unwrap().seq - 1)
                    .collect::<Vec<_>>(),
                expected_offsets
            );
            assert!(decoys.iter().all(|packet| packet.ip.ttl == 4));
            validate_payload_decoy_runtime_safety(&original, &decoys, Some(10)).unwrap();
        }
    }

    #[test]
    fn tcp_fragment_tree_requires_expiring_ttl_and_nonzero_split() {
        for dsl in [
            r"[TCP:flags:PA]-duplicate(fragment{TCP:3:in-order}(,),)-| \/",
            r"[TCP:flags:PA]-duplicate(tamper{IP:ttl:replace:4}(fragment{TCP:0:in-order}(,)),)-| \/",
        ] {
            assert!(
                GenevaStrategy::from_dsl(dsl).is_err(),
                "accepted unsafe {dsl}"
            );
        }
    }

    #[test]
    fn tcp_fragment_offsets_must_fit_the_runtime_payload_before_any_send() {
        let context = SendFirstContext {
            dst: "203.0.113.10:443".parse().unwrap(),
            reference_path_hops: Some(10),
        };
        for order in ["in-order", "reversed"] {
            for offset in [3, 4] {
                let dsl = format!(
                    "[TCP:flags:PA]-duplicate(tamper{{IP:ttl:replace:4}}(fragment{{TCP:{offset}:{order}}}(,)),)-| \\/"
                );
                let strategy = GenevaStrategy::from_dsl(&dsl).unwrap();
                let error = strategy
                    .preflight_send_first(b"abc", None, &context)
                    .expect_err("empty fragment must fail during preflight");
                assert!(error.to_string().contains("empty live decoy segment"));
            }
        }
    }

    #[test]
    fn nested_tcp_fragment_empty_branch_fails_during_preflight() {
        let dsl = "[TCP:flags:PA]-duplicate(tamper{IP:ttl:replace:4}(fragment{TCP:2:reversed}(fragment{TCP:2:in-order}(,),)),)-| \\/";
        let strategy = GenevaStrategy::from_dsl(dsl).unwrap();
        let context = SendFirstContext {
            dst: "203.0.113.10:443".parse().unwrap(),
            reference_path_hops: Some(10),
        };
        let error = strategy
            .preflight_send_first(b"abc", None, &context)
            .expect_err("nested empty fragment must fail during preflight");
        assert!(error.to_string().contains("empty live decoy segment"));
    }

    #[test]
    fn duplicate_two_pass_branches_keeps_exactly_one_raw_duplicate() {
        let program = GenevaProgram::parse(r"[TCP:flags:PA]-duplicate(,)-| \/").unwrap();
        let mut rng = StdRng::seed_from_u64(0);
        let original = GenevaStrategy::model_packet(b"hello");
        let decoys = project_decoys(&program, &original, &mut rng).expect("duplicate plan");
        assert_eq!(decoys, vec![original]);
    }
}
