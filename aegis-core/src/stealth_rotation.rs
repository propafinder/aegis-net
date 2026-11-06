use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DriftSurface {
    LocalState,
    DirectFingerprint,
    RelaySession,
    RelayTransportOrder,
    RelayUdpTransportOrder,
    RelayWebsocketPath,
    RelayGrpcPath,
    RelayMasquePath,
}

const PHASE_SLOT_COUNT: u64 = 17;

pub fn current_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub fn surface_epoch(base_epoch_secs: u64, now_secs: u64, surface: DriftSurface) -> u64 {
    let base_epoch_secs = base_epoch_secs.max(1);
    now_secs.saturating_add(surface_phase_offset(base_epoch_secs, surface)) / base_epoch_secs
}

pub fn next_surface_rotation_at(base_epoch_secs: u64, now_secs: u64, surface: DriftSurface) -> u64 {
    let base_epoch_secs = base_epoch_secs.max(1);
    let offset = surface_phase_offset(base_epoch_secs, surface);
    let shifted_now = now_secs.saturating_add(offset);
    shifted_now
        .saturating_div(base_epoch_secs)
        .saturating_add(1)
        .saturating_mul(base_epoch_secs)
        .saturating_sub(offset)
}

pub fn surface_phase_offset(base_epoch_secs: u64, surface: DriftSurface) -> u64 {
    if base_epoch_secs <= 1 {
        return 0;
    }
    let slot = match surface {
        DriftSurface::LocalState => 1,
        DriftSurface::DirectFingerprint => 4,
        DriftSurface::RelaySession => 7,
        DriftSurface::RelayTransportOrder => 9,
        DriftSurface::RelayUdpTransportOrder => 11,
        DriftSurface::RelayWebsocketPath => 3,
        DriftSurface::RelayGrpcPath => 6,
        DriftSurface::RelayMasquePath => 13,
    };
    let offset = base_epoch_secs.saturating_mul(slot) / PHASE_SLOT_COUNT;
    offset.min(base_epoch_secs - 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_surface_offsets_stay_distinct() {
        let base = 900;
        let local = surface_phase_offset(base, DriftSurface::LocalState);
        let direct = surface_phase_offset(base, DriftSurface::DirectFingerprint);
        let relay = surface_phase_offset(base, DriftSurface::RelaySession);
        assert_ne!(local, direct);
        assert_ne!(local, relay);
        assert_ne!(direct, relay);
    }

    #[test]
    fn next_rotation_times_do_not_move_together() {
        let base = 900;
        let now = 10_000;
        let local = next_surface_rotation_at(base, now, DriftSurface::LocalState);
        let direct = next_surface_rotation_at(base, now, DriftSurface::DirectFingerprint);
        let relay = next_surface_rotation_at(base, now, DriftSurface::RelaySession);
        assert_ne!(local, direct);
        assert_ne!(local, relay);
        assert_ne!(direct, relay);
    }

    #[test]
    fn surface_epoch_is_stable_inside_same_shifted_window() {
        let base = 900;
        let start = 20_000;
        let a = surface_epoch(base, start, DriftSurface::RelayWebsocketPath);
        let b = surface_epoch(base, start + 30, DriftSurface::RelayWebsocketPath);
        assert_eq!(a, b);
    }
}
