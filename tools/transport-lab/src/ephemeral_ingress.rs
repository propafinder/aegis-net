//! Bounded, deterministic admission rotation inspired by CensorLess.
//!
//! This is a laboratory model, not an AWS transport or a cryptographic verifier.
//! A caller must verify controller signatures, relay identity, and TLS authority
//! before constructing `TrustedControllerInput`. No carrier migration or payload
//! replay exists here: an authenticated session stays on its original bridge.

use std::collections::BTreeMap;
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct BridgeId(pub u64);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct SessionId(pub u64);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BridgePhase {
    Prepared,
    Active,
    Draining,
    Retired,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloseReason {
    Finished,
    PreAuthDeadline,
    AuthenticationDeadline,
    AttemptsExhausted,
    AuthFailure,
    CarrierLost,
    DrainExpired,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionPhase {
    PreAuth,
    AuthStarted,
    Open,
    Closed(CloseReason),
}

/// The laboratory's externally established trust precondition. These fields do
/// not verify a signature. Production code must use its own verified descriptor
/// boundary rather than interpreting this input as authentication evidence.
#[derive(Debug, Clone, Copy)]
pub struct TrustedControllerInput {
    pub bridge: BridgeId,
    pub epoch: u64,
    /// Absolute monotonic tick, derived locally from a verified bounded TTL.
    pub expires_at_ms: u64,
}

#[derive(Debug, Clone, Copy)]
pub struct RotationLimits {
    pub max_bridges: usize,
    pub max_sessions: usize,
    pub max_descriptor_ttl_ms: u64,
    pub establishment_timeout_ms: u64,
    pub drain_timeout_ms: u64,
    pub max_pre_auth_attempts: u32,
}

impl Default for RotationLimits {
    fn default() -> Self {
        Self {
            max_bridges: 8,
            max_sessions: 32,
            max_descriptor_ttl_ms: 60_000,
            establishment_timeout_ms: 15_000,
            drain_timeout_ms: 30_000,
            max_pre_auth_attempts: 2,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModelError {
    InvalidLimits,
    TimeReversed,
    ArithmeticOverflow,
    StaleEpoch,
    InvalidTtl,
    DuplicateBridge,
    UnknownBridge,
    BridgeCapacity,
    SessionCapacity,
    DuplicateSession,
    UnknownSession,
    NoValidAdmission,
    InvalidTransition,
    ReplayForbidden,
    AttemptsExhausted,
    RequestTooLarge,
    RequestBudgetExhausted,
    ByteBudgetExhausted,
    RuntimeBudgetExhausted,
    ConcurrencyExhausted,
    UnknownReservation,
}

impl fmt::Display for ModelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for ModelError {}

#[derive(Debug, Clone, Copy)]
struct Bridge {
    phase: BridgePhase,
    epoch: u64,
    expires_at_ms: u64,
    drain_deadline_ms: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionSnapshot {
    pub bridge: BridgeId,
    pub phase: SessionPhase,
    pub attempts: u32,
    pub establishment_deadline_ms: u64,
}

/// Typed failures that certify that no device identity/authentication/open was
/// attempted. An arbitrary I/O error after authentication is not one of these.
#[derive(Debug, Clone, Copy)]
pub enum SafePreAuthFailure {
    ConnectFailedBeforeIdentity,
    TlsRejectedBeforeIdentity,
    CarrierUnavailableBeforeIdentity,
}

pub struct RotationModel {
    limits: RotationLimits,
    bridges: BTreeMap<BridgeId, Bridge>,
    sessions: BTreeMap<SessionId, SessionSnapshot>,
    active: Option<BridgeId>,
    highest_epoch: u64,
    highest_session_id: Option<u64>,
    last_tick_ms: u64,
}

impl RotationModel {
    pub fn new(limits: RotationLimits) -> Result<Self, ModelError> {
        if limits.max_bridges == 0
            || limits.max_sessions == 0
            || limits.max_descriptor_ttl_ms == 0
            || limits.establishment_timeout_ms == 0
            || limits.drain_timeout_ms == 0
            || limits.max_pre_auth_attempts == 0
        {
            return Err(ModelError::InvalidLimits);
        }
        Ok(Self {
            limits,
            bridges: BTreeMap::new(),
            sessions: BTreeMap::new(),
            active: None,
            highest_epoch: 0,
            highest_session_id: None,
            last_tick_ms: 0,
        })
    }

    /// Expired descriptors stop admission. Existing committed sessions receive
    /// a bounded drain on their existing carrier, never a replacement carrier.
    pub fn tick(&mut self, now_ms: u64) -> Result<(), ModelError> {
        if now_ms < self.last_tick_ms {
            return Err(ModelError::TimeReversed);
        }
        // Compute before changing state so an overflow cannot leave a partial
        // transition. Saturation would otherwise create an effectively infinite
        // drain lease near the end of the clock range.
        let expired_active = self.active.filter(|id| {
            self.bridges
                .get(id)
                .is_some_and(|bridge| bridge.expires_at_ms <= now_ms)
        });
        let expiry_drain = if let Some(id) = expired_active {
            Some(
                self.bridges
                    .get(&id)
                    .expect("active bridge exists")
                    .expires_at_ms
                    .checked_add(self.limits.drain_timeout_ms)
                    .ok_or(ModelError::ArithmeticOverflow)?,
            )
        } else {
            None
        };
        self.last_tick_ms = now_ms;
        if let Some(id) = expired_active {
            let bridge = self.bridges.get_mut(&id).expect("active bridge exists");
            bridge.phase = BridgePhase::Draining;
            bridge.drain_deadline_ms = expiry_drain;
            self.active = None;
        }
        for bridge in self.bridges.values_mut() {
            if bridge.phase == BridgePhase::Prepared && bridge.expires_at_ms <= now_ms {
                bridge.phase = BridgePhase::Retired;
            }
        }
        for session in self.sessions.values_mut() {
            if session.phase == SessionPhase::PreAuth && session.establishment_deadline_ms <= now_ms
            {
                session.phase = SessionPhase::Closed(CloseReason::PreAuthDeadline);
            } else if session.phase == SessionPhase::AuthStarted
                && session.establishment_deadline_ms <= now_ms
            {
                session.phase = SessionPhase::Closed(CloseReason::AuthenticationDeadline);
            }
        }
        for (id, bridge) in &mut self.bridges {
            if bridge.phase != BridgePhase::Draining {
                continue;
            }
            let has_live_sessions = self.sessions.values().any(|session| {
                session.bridge == *id && !matches!(session.phase, SessionPhase::Closed(_))
            });
            if bridge
                .drain_deadline_ms
                .is_some_and(|deadline| deadline <= now_ms)
            {
                for session in self.sessions.values_mut().filter(|s| s.bridge == *id) {
                    if !matches!(session.phase, SessionPhase::Closed(_)) {
                        session.phase = SessionPhase::Closed(CloseReason::DrainExpired);
                    }
                }
                bridge.phase = BridgePhase::Retired;
            } else if !has_live_sessions {
                bridge.phase = BridgePhase::Retired;
            }
        }
        Ok(())
    }

    pub fn prepare(
        &mut self,
        input: TrustedControllerInput,
        now_ms: u64,
    ) -> Result<(), ModelError> {
        self.tick(now_ms)?;
        if input.epoch <= self.highest_epoch {
            return Err(ModelError::StaleEpoch);
        }
        let ttl = input
            .expires_at_ms
            .checked_sub(now_ms)
            .filter(|ttl| *ttl > 0 && *ttl <= self.limits.max_descriptor_ttl_ms)
            .ok_or(ModelError::InvalidTtl)?;
        // Keep the checked subtraction explicit; wall-clock expiries must not
        // be passed through as a new full TTL when an old update is replayed.
        let _ = ttl;
        // Expiry must remain processable after activation. Admitting a
        // descriptor whose drain deadline overflows would strand its live
        // sessions when tick/close later tries to expire it.
        input
            .expires_at_ms
            .checked_add(self.limits.drain_timeout_ms)
            .ok_or(ModelError::ArithmeticOverflow)?;
        if self.bridges.contains_key(&input.bridge) {
            return Err(ModelError::DuplicateBridge);
        }
        if self.bridges.len() >= self.limits.max_bridges {
            return Err(ModelError::BridgeCapacity);
        }
        self.bridges.insert(
            input.bridge,
            Bridge {
                phase: BridgePhase::Prepared,
                epoch: input.epoch,
                expires_at_ms: input.expires_at_ms,
                drain_deadline_ms: None,
            },
        );
        self.highest_epoch = input.epoch;
        Ok(())
    }

    pub fn activate(&mut self, id: BridgeId, now_ms: u64) -> Result<(), ModelError> {
        self.tick(now_ms)?;
        let next = self.bridges.get(&id).ok_or(ModelError::UnknownBridge)?;
        if next.phase != BridgePhase::Prepared || next.expires_at_ms <= now_ms {
            return Err(ModelError::InvalidTransition);
        }
        if next.epoch != self.highest_epoch {
            return Err(ModelError::StaleEpoch);
        }
        let deadline = now_ms
            .checked_add(self.limits.drain_timeout_ms)
            .ok_or(ModelError::ArithmeticOverflow)?;
        if let Some(previous) = self.active {
            let old = self
                .bridges
                .get_mut(&previous)
                .expect("active bridge exists");
            old.phase = BridgePhase::Draining;
            old.drain_deadline_ms = Some(deadline);
        }
        self.bridges.get_mut(&id).expect("validated bridge").phase = BridgePhase::Active;
        self.active = Some(id);
        Ok(())
    }

    fn admitted_bridge(&self, now_ms: u64) -> Result<BridgeId, ModelError> {
        let id = self.active.ok_or(ModelError::NoValidAdmission)?;
        let bridge = self.bridges.get(&id).ok_or(ModelError::NoValidAdmission)?;
        if bridge.phase != BridgePhase::Active || bridge.expires_at_ms <= now_ms {
            return Err(ModelError::NoValidAdmission);
        }
        Ok(id)
    }

    pub fn start_session(&mut self, id: SessionId, now_ms: u64) -> Result<(), ModelError> {
        self.tick(now_ms)?;
        let bridge = self.admitted_bridge(now_ms)?;
        if self.sessions.contains_key(&id)
            || self
                .highest_session_id
                .is_some_and(|previous| id.0 <= previous)
        {
            return Err(ModelError::DuplicateSession);
        }
        if self.sessions.len() >= self.limits.max_sessions {
            return Err(ModelError::SessionCapacity);
        }
        let deadline = now_ms
            .checked_add(self.limits.establishment_timeout_ms)
            .ok_or(ModelError::ArithmeticOverflow)?;
        self.sessions.insert(
            id,
            SessionSnapshot {
                bridge,
                phase: SessionPhase::PreAuth,
                attempts: 1,
                establishment_deadline_ms: deadline,
            },
        );
        self.highest_session_id = Some(id.0);
        Ok(())
    }

    /// Safe retry preserves the original total establishment deadline. It
    /// cannot be invoked after AuthStarted even when zero bytes were counted.
    pub fn retry_before_auth(
        &mut self,
        id: SessionId,
        _failure: SafePreAuthFailure,
        now_ms: u64,
    ) -> Result<(), ModelError> {
        self.tick(now_ms)?;
        let current = self.sessions.get(&id).ok_or(ModelError::UnknownSession)?;
        if current.phase != SessionPhase::PreAuth {
            return Err(ModelError::ReplayForbidden);
        }
        if current.attempts >= self.limits.max_pre_auth_attempts {
            self.sessions.get_mut(&id).expect("validated session").phase =
                SessionPhase::Closed(CloseReason::AttemptsExhausted);
            return Err(ModelError::AttemptsExhausted);
        }
        let bridge = self.admitted_bridge(now_ms)?;
        let session = self.sessions.get_mut(&id).expect("validated session");
        session.bridge = bridge;
        session.attempts += 1;
        Ok(())
    }

    pub fn begin_auth(&mut self, id: SessionId, now_ms: u64) -> Result<(), ModelError> {
        self.tick(now_ms)?;
        let active = self.admitted_bridge(now_ms)?;
        let session = self
            .sessions
            .get_mut(&id)
            .ok_or(ModelError::UnknownSession)?;
        if session.phase != SessionPhase::PreAuth || session.bridge != active {
            return Err(ModelError::InvalidTransition);
        }
        session.phase = SessionPhase::AuthStarted;
        Ok(())
    }

    pub fn confirm_open(&mut self, id: SessionId, now_ms: u64) -> Result<(), ModelError> {
        self.tick(now_ms)?;
        let session = self
            .sessions
            .get_mut(&id)
            .ok_or(ModelError::UnknownSession)?;
        if session.phase != SessionPhase::AuthStarted {
            return Err(ModelError::InvalidTransition);
        }
        // Completing an already committed open on a draining carrier is valid;
        // changing its bridge or replaying the open on the new carrier is not.
        session.phase = SessionPhase::Open;
        Ok(())
    }

    pub fn close(
        &mut self,
        id: SessionId,
        reason: CloseReason,
        now_ms: u64,
    ) -> Result<(), ModelError> {
        self.tick(now_ms)?;
        let session = self
            .sessions
            .get_mut(&id)
            .ok_or(ModelError::UnknownSession)?;
        if matches!(session.phase, SessionPhase::Closed(_)) {
            return Err(ModelError::InvalidTransition);
        }
        session.phase = SessionPhase::Closed(reason);
        Ok(())
    }

    pub fn session(&self, id: SessionId) -> Option<SessionSnapshot> {
        self.sessions.get(&id).copied()
    }

    pub fn bridge_phase(&self, id: BridgeId) -> Option<BridgePhase> {
        self.bridges.get(&id).map(|bridge| bridge.phase)
    }

    /// Explicit bounded-history cleanup never reduces the trusted epoch.
    pub fn forget_closed_session(&mut self, id: SessionId) -> Result<(), ModelError> {
        if !self
            .sessions
            .get(&id)
            .is_some_and(|s| matches!(s.phase, SessionPhase::Closed(_)))
        {
            return Err(ModelError::InvalidTransition);
        }
        self.sessions.remove(&id);
        Ok(())
    }

    pub fn forget_retired_bridge(&mut self, id: BridgeId) -> Result<(), ModelError> {
        if self.bridge_phase(id) != Some(BridgePhase::Retired)
            || self.sessions.values().any(|s| s.bridge == id)
        {
            return Err(ModelError::InvalidTransition);
        }
        self.bridges.remove(&id);
        Ok(())
    }
}

#[derive(Debug, Clone, Copy)]
pub struct RequestLimits {
    pub max_requests: u64,
    pub max_reserved_wire_bytes: u64,
    pub max_request_wire_bytes: u64,
    pub max_in_flight: usize,
    pub max_operation_ms: u64,
    pub max_reserved_runtime_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct ReservationId(pub u64);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RequestReservation {
    pub id: ReservationId,
    pub encoded_wire_byte_cap: u64,
    pub deadline_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BudgetSnapshot {
    pub reserved_requests: u64,
    pub reserved_wire_bytes: u64,
    pub reserved_runtime_ms: u64,
    pub in_flight: usize,
}

/// Reserve the full encoded request+response caps before submitting an
/// operation. Completion only releases concurrency. Unconfirmed cancellation
/// cannot refund requests, bytes, time, or an outstanding execution slot.
pub struct RequestBudget {
    limits: RequestLimits,
    reserved_requests: u64,
    reserved_wire_bytes: u64,
    reserved_runtime_ms: u64,
    in_flight: BTreeMap<ReservationId, RequestReservation>,
    last_tick_ms: u64,
}

impl RequestBudget {
    pub fn new(limits: RequestLimits) -> Result<Self, ModelError> {
        if limits.max_requests == 0
            || limits.max_reserved_wire_bytes == 0
            || limits.max_request_wire_bytes == 0
            || limits.max_in_flight == 0
            || limits.max_operation_ms == 0
            || limits.max_reserved_runtime_ms == 0
        {
            return Err(ModelError::InvalidLimits);
        }
        Ok(Self {
            limits,
            reserved_requests: 0,
            reserved_wire_bytes: 0,
            reserved_runtime_ms: 0,
            in_flight: BTreeMap::new(),
            last_tick_ms: 0,
        })
    }

    pub fn reserve(
        &mut self,
        encoded_request_and_response_cap: u64,
        operation_timeout_ms: u64,
        now_ms: u64,
    ) -> Result<RequestReservation, ModelError> {
        if now_ms < self.last_tick_ms {
            return Err(ModelError::TimeReversed);
        }
        self.last_tick_ms = now_ms;
        if encoded_request_and_response_cap == 0
            || encoded_request_and_response_cap > self.limits.max_request_wire_bytes
            || operation_timeout_ms == 0
            || operation_timeout_ms > self.limits.max_operation_ms
        {
            return Err(ModelError::RequestTooLarge);
        }
        if self.in_flight.len() >= self.limits.max_in_flight {
            return Err(ModelError::ConcurrencyExhausted);
        }
        let requests = self
            .reserved_requests
            .checked_add(1)
            .ok_or(ModelError::ArithmeticOverflow)?;
        let bytes = self
            .reserved_wire_bytes
            .checked_add(encoded_request_and_response_cap)
            .ok_or(ModelError::ArithmeticOverflow)?;
        let runtime = self
            .reserved_runtime_ms
            .checked_add(operation_timeout_ms)
            .ok_or(ModelError::ArithmeticOverflow)?;
        let deadline = now_ms
            .checked_add(operation_timeout_ms)
            .ok_or(ModelError::ArithmeticOverflow)?;
        if requests > self.limits.max_requests {
            return Err(ModelError::RequestBudgetExhausted);
        }
        if bytes > self.limits.max_reserved_wire_bytes {
            return Err(ModelError::ByteBudgetExhausted);
        }
        if runtime > self.limits.max_reserved_runtime_ms {
            return Err(ModelError::RuntimeBudgetExhausted);
        }
        let reservation = RequestReservation {
            id: ReservationId(requests),
            encoded_wire_byte_cap: encoded_request_and_response_cap,
            deadline_ms: deadline,
        };
        self.reserved_requests = requests;
        self.reserved_wire_bytes = bytes;
        self.reserved_runtime_ms = runtime;
        self.in_flight.insert(reservation.id, reservation);
        Ok(reservation)
    }

    /// Caller must have confirmation that the remote execution has stopped.
    /// A local socket close or elapsed deadline is insufficient confirmation.
    pub fn complete_confirmed(&mut self, id: ReservationId) -> Result<(), ModelError> {
        if self.in_flight.remove(&id).is_none() {
            return Err(ModelError::UnknownReservation);
        }
        Ok(())
    }

    pub fn cancel_unconfirmed(&self, id: ReservationId) -> Result<(), ModelError> {
        if !self.in_flight.contains_key(&id) {
            return Err(ModelError::UnknownReservation);
        }
        Ok(())
    }

    pub fn snapshot(&self) -> BudgetSnapshot {
        BudgetSnapshot {
            reserved_requests: self.reserved_requests,
            reserved_wire_bytes: self.reserved_wire_bytes,
            reserved_runtime_ms: self.reserved_runtime_ms,
            in_flight: self.in_flight.len(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn model() -> RotationModel {
        RotationModel::new(RotationLimits {
            max_descriptor_ttl_ms: 1_000,
            establishment_timeout_ms: 50,
            drain_timeout_ms: 30,
            ..RotationLimits::default()
        })
        .unwrap()
    }

    fn prepare(model: &mut RotationModel, bridge: u64, epoch: u64, expires: u64, now: u64) {
        model
            .prepare(
                TrustedControllerInput {
                    bridge: BridgeId(bridge),
                    epoch,
                    expires_at_ms: expires,
                },
                now,
            )
            .unwrap();
    }

    fn active_model() -> RotationModel {
        let mut model = model();
        prepare(&mut model, 1, 1, 100, 0);
        model.activate(BridgeId(1), 1).unwrap();
        model
    }

    #[test]
    fn prepared_bridge_and_uncommitted_session_cannot_skip_admission_or_auth() {
        let mut model = model();
        prepare(&mut model, 1, 1, 100, 0);
        assert_eq!(
            model.start_session(SessionId(1), 1),
            Err(ModelError::NoValidAdmission)
        );
        model.activate(BridgeId(1), 2).unwrap();
        model.start_session(SessionId(1), 3).unwrap();
        assert_eq!(
            model.confirm_open(SessionId(1), 4),
            Err(ModelError::InvalidTransition)
        );
        assert_eq!(model.bridge_phase(BridgeId(1)), Some(BridgePhase::Active));
        assert_eq!(
            model.activate(BridgeId(1), 5),
            Err(ModelError::InvalidTransition)
        );
    }

    #[test]
    fn auth_started_with_zero_payload_bytes_never_replays_on_new_bridge() {
        let mut model = active_model();
        model.start_session(SessionId(1), 2).unwrap();
        model.begin_auth(SessionId(1), 3).unwrap();
        prepare(&mut model, 2, 2, 150, 4);
        model.activate(BridgeId(2), 5).unwrap();
        assert_eq!(
            model.retry_before_auth(
                SessionId(1),
                SafePreAuthFailure::CarrierUnavailableBeforeIdentity,
                6,
            ),
            Err(ModelError::ReplayForbidden)
        );
        assert_eq!(model.session(SessionId(1)).unwrap().bridge, BridgeId(1));
        model
            .close(SessionId(1), CloseReason::AuthFailure, 7)
            .unwrap();
        assert_eq!(
            model.retry_before_auth(
                SessionId(1),
                SafePreAuthFailure::TlsRejectedBeforeIdentity,
                8
            ),
            Err(ModelError::ReplayForbidden)
        );
        assert_eq!(
            model.start_session(SessionId(1), 9),
            Err(ModelError::DuplicateSession)
        );
    }

    #[test]
    fn rotation_keeps_old_open_carrier_and_enforces_drain_deadline() {
        let mut model = active_model();
        model.start_session(SessionId(1), 2).unwrap();
        model.begin_auth(SessionId(1), 3).unwrap();
        model.confirm_open(SessionId(1), 4).unwrap();
        prepare(&mut model, 2, 2, 150, 5);
        model.activate(BridgeId(2), 6).unwrap();
        model.start_session(SessionId(2), 7).unwrap();
        assert_eq!(model.session(SessionId(2)).unwrap().bridge, BridgeId(2));
        model.tick(35).unwrap();
        assert_eq!(
            model.session(SessionId(1)).unwrap().phase,
            SessionPhase::Open
        );
        assert_eq!(model.session(SessionId(1)).unwrap().bridge, BridgeId(1));
        model.tick(36).unwrap();
        assert_eq!(
            model.session(SessionId(1)).unwrap().phase,
            SessionPhase::Closed(CloseReason::DrainExpired)
        );
        assert_eq!(model.bridge_phase(BridgeId(1)), Some(BridgePhase::Retired));
    }

    #[test]
    fn expired_controller_input_cannot_extend_admission_and_clock_cannot_reverse() {
        let mut model = active_model();
        model.start_session(SessionId(1), 2).unwrap();
        model.begin_auth(SessionId(1), 3).unwrap();
        model.confirm_open(SessionId(1), 4).unwrap();
        assert_eq!(
            model.start_session(SessionId(2), 100),
            Err(ModelError::NoValidAdmission)
        );
        assert_eq!(
            model.session(SessionId(1)).unwrap().phase,
            SessionPhase::Open
        );
        assert_eq!(model.tick(99), Err(ModelError::TimeReversed));
        assert_eq!(
            model.prepare(
                TrustedControllerInput {
                    bridge: BridgeId(2),
                    epoch: 2,
                    expires_at_ms: 100,
                },
                100,
            ),
            Err(ModelError::InvalidTtl)
        );
        model.tick(130).unwrap();
        assert_eq!(
            model.session(SessionId(1)).unwrap().phase,
            SessionPhase::Closed(CloseReason::DrainExpired)
        );
    }

    #[test]
    fn stale_epoch_rejected_after_history_cleanup_and_rollback_requires_new_epoch() {
        let mut model = active_model();
        prepare(&mut model, 2, 2, 150, 2);
        model.activate(BridgeId(2), 3).unwrap();
        model.tick(4).unwrap();
        model.forget_retired_bridge(BridgeId(1)).unwrap();
        assert_eq!(
            model.prepare(
                TrustedControllerInput {
                    bridge: BridgeId(1),
                    epoch: 1,
                    expires_at_ms: 200,
                },
                5,
            ),
            Err(ModelError::StaleEpoch)
        );
        prepare(&mut model, 1, 3, 200, 6);
        model.activate(BridgeId(1), 7).unwrap();
        model.start_session(SessionId(1), 8).unwrap();
        assert_eq!(model.session(SessionId(1)).unwrap().bridge, BridgeId(1));
    }

    #[test]
    fn older_prepared_update_cannot_be_published_after_a_newer_trusted_update() {
        let mut model = model();
        prepare(&mut model, 1, 1, 100, 0);
        prepare(&mut model, 2, 2, 100, 1);
        assert_eq!(model.activate(BridgeId(1), 2), Err(ModelError::StaleEpoch));
        model.activate(BridgeId(2), 3).unwrap();
    }

    #[test]
    fn late_tick_uses_original_expiry_and_authentication_is_deadline_bounded() {
        let mut model = active_model();
        model.start_session(SessionId(1), 2).unwrap();
        model.begin_auth(SessionId(1), 3).unwrap();
        model.tick(52).unwrap();
        assert_eq!(
            model.session(SessionId(1)).unwrap().phase,
            SessionPhase::Closed(CloseReason::AuthenticationDeadline)
        );
        model.start_session(SessionId(2), 53).unwrap();
        model.begin_auth(SessionId(2), 54).unwrap();
        model.confirm_open(SessionId(2), 55).unwrap();
        model.tick(300).unwrap();
        assert_eq!(model.bridge_phase(BridgeId(1)), Some(BridgePhase::Retired));
        assert_eq!(
            model.session(SessionId(2)).unwrap().phase,
            SessionPhase::Closed(CloseReason::DrainExpired)
        );
        model.forget_closed_session(SessionId(2)).unwrap();
        prepare(&mut model, 2, 2, 400, 301);
        model.activate(BridgeId(2), 302).unwrap();
        assert_eq!(
            model.start_session(SessionId(2), 303),
            Err(ModelError::DuplicateSession)
        );
    }

    #[test]
    fn safe_retry_is_bounded_and_preserves_whole_establishment_deadline() {
        let mut model = active_model();
        model.start_session(SessionId(1), 2).unwrap();
        prepare(&mut model, 2, 2, 150, 3);
        model.activate(BridgeId(2), 4).unwrap();
        model
            .retry_before_auth(
                SessionId(1),
                SafePreAuthFailure::ConnectFailedBeforeIdentity,
                5,
            )
            .unwrap();
        let session = model.session(SessionId(1)).unwrap();
        assert_eq!(session.bridge, BridgeId(2));
        assert_eq!(session.establishment_deadline_ms, 52);
        assert_eq!(session.attempts, 2);
        assert_eq!(
            model.retry_before_auth(
                SessionId(1),
                SafePreAuthFailure::ConnectFailedBeforeIdentity,
                6
            ),
            Err(ModelError::AttemptsExhausted)
        );
        model.start_session(SessionId(2), 7).unwrap();
        model.tick(57).unwrap();
        assert_eq!(
            model.begin_auth(SessionId(2), 57),
            Err(ModelError::InvalidTransition)
        );
    }

    fn budget(limits: RequestLimits) -> RequestBudget {
        RequestBudget::new(limits).unwrap()
    }

    fn request_limits() -> RequestLimits {
        RequestLimits {
            max_requests: 2,
            max_reserved_wire_bytes: 100,
            max_request_wire_bytes: 80,
            max_in_flight: 1,
            max_operation_ms: 15,
            max_reserved_runtime_ms: 30,
        }
    }

    #[test]
    fn unconfirmed_cancel_and_elapsed_deadline_do_not_refund_reservations() {
        let mut budget = budget(request_limits());
        let first = budget.reserve(70, 15, 0).unwrap();
        let before = budget.snapshot();
        budget.cancel_unconfirmed(first.id).unwrap();
        assert_eq!(budget.snapshot(), before);
        assert_eq!(
            budget.reserve(1, 1, 16),
            Err(ModelError::ConcurrencyExhausted)
        );
        budget.complete_confirmed(first.id).unwrap();
        assert_eq!(budget.snapshot().reserved_wire_bytes, 70);
        assert_eq!(
            budget.reserve(31, 15, 17),
            Err(ModelError::ByteBudgetExhausted)
        );
        let second = budget.reserve(30, 15, 18).unwrap();
        budget.complete_confirmed(second.id).unwrap();
        assert_eq!(
            budget.reserve(1, 1, 19),
            Err(ModelError::RequestBudgetExhausted)
        );
        assert_eq!(budget.snapshot().reserved_requests, 2);
        assert_eq!(budget.snapshot().reserved_runtime_ms, 30);
    }

    #[test]
    fn budgets_reject_expanded_wire_body_runtime_overflow_and_time_reversal_atomically() {
        let mut limits = request_limits();
        limits.max_reserved_runtime_ms = 15;
        let mut budget = budget(limits);
        assert_eq!(budget.reserve(81, 1, 1), Err(ModelError::RequestTooLarge));
        assert_eq!(budget.snapshot().reserved_requests, 0);
        let first = budget.reserve(10, 10, 2).unwrap();
        budget.complete_confirmed(first.id).unwrap();
        let before = budget.snapshot();
        assert_eq!(
            budget.reserve(10, 6, 3),
            Err(ModelError::RuntimeBudgetExhausted)
        );
        assert_eq!(budget.snapshot(), before);
        assert_eq!(budget.reserve(10, 1, 2), Err(ModelError::TimeReversed));
        assert_eq!(
            budget.reserve(10, 1, u64::MAX),
            Err(ModelError::ArithmeticOverflow)
        );
        assert_eq!(budget.snapshot(), before);
    }

    #[test]
    fn model_collections_are_bounded_and_only_terminal_history_can_be_removed() {
        let mut model = RotationModel::new(RotationLimits {
            max_bridges: 1,
            max_sessions: 1,
            ..RotationLimits::default()
        })
        .unwrap();
        prepare(&mut model, 1, 1, 100, 0);
        model.activate(BridgeId(1), 1).unwrap();
        model.start_session(SessionId(1), 2).unwrap();
        assert_eq!(
            model.start_session(SessionId(2), 3),
            Err(ModelError::SessionCapacity)
        );
        assert_eq!(
            model.forget_closed_session(SessionId(1)),
            Err(ModelError::InvalidTransition)
        );
        assert_eq!(
            model.prepare(
                TrustedControllerInput {
                    bridge: BridgeId(2),
                    epoch: 2,
                    expires_at_ms: 100,
                },
                4,
            ),
            Err(ModelError::BridgeCapacity)
        );
        model
            .close(SessionId(1), CloseReason::CarrierLost, 5)
            .unwrap();
        model.forget_closed_session(SessionId(1)).unwrap();
        model.start_session(SessionId(2), 6).unwrap();
    }
}
