//! Synthetic rotation only: no cloud transport or cryptographic verification.
use aegis_transport_lab::ephemeral_ingress::{
    BridgeId, BridgePhase, ModelError, RotationLimits, RotationModel, SessionId, SessionPhase,
    TrustedControllerInput,
};

#[test]
fn unrepresentable_expiry_drain_cannot_strand_an_open_session() {
    let mut model = RotationModel::new(RotationLimits {
        max_descriptor_ttl_ms: 1_000,
        establishment_timeout_ms: 50,
        drain_timeout_ms: 30,
        ..RotationLimits::default()
    })
    .unwrap();
    let now = u64::MAX - 100;
    let expires = u64::MAX - 1;

    // Either refuse an admission whose eventual drain cannot be represented,
    // or ensure an accepted descriptor still reaches a terminal state.
    match model.prepare(
        TrustedControllerInput {
            bridge: BridgeId(1),
            epoch: 1,
            expires_at_ms: expires,
        },
        now,
    ) {
        Err(ModelError::ArithmeticOverflow) => return,
        other => other.unwrap(),
    }
    model.activate(BridgeId(1), now + 1).unwrap();
    model.start_session(SessionId(1), now + 2).unwrap();
    model.begin_auth(SessionId(1), now + 3).unwrap();
    model.confirm_open(SessionId(1), now + 4).unwrap();

    let expiry_result = model.tick(expires);
    assert_ne!(
        model.bridge_phase(BridgeId(1)),
        Some(BridgePhase::Active),
        "expiry returned {expiry_result:?} but retained an active bridge"
    );
    assert!(
        matches!(
            model.session(SessionId(1)).unwrap().phase,
            SessionPhase::Closed(_)
        ),
        "an accepted unrepresentable drain must fail closed"
    );
}
