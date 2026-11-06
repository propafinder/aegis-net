#!/usr/bin/env bash
# Contract test for the Track C anti-anomaly acceptance summary helper.
# The test builds two fixture repos (baseline-shape vs "all improvements landed")
# and asserts the rubric reacts in the expected direction. The real repo check
# lives at the end — composite score must be finite, verdict one of the three
# documented values, and next_action must reference a documented slice.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SCRIPT="${ROOT}/scripts/build-stealth-anti-anomaly-acceptance-summary.sh"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/aegis-anti-anomaly-summary.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT

require_file_contains() {
  local file="$1"
  local expected="$2"
  if ! grep -Fq -- "${expected}" "${file}"; then
    echo "expected ${file} to contain: ${expected}" >&2
    echo "--- ${file} ---" >&2
    cat "${file}" >&2
    exit 1
  fi
}

############################################
# Fixture 1: synthetic weak baseline (direct=4 / relay=2 / no pools / no drift)
############################################

FIX1="${TMP_DIR}/fix1"
mkdir -p "${FIX1}/aegis-client/src/direct" \
         "${FIX1}/aegis-client/src/relay" \
         "${FIX1}/aegis-client/src" \
         "${FIX1}/aegis-core/src" \
         "${FIX1}/aegis-core/src/strategies"

cat > "${FIX1}/aegis-client/src/direct/planner.rs" <<'EOF'
const DIRECT_PROFILE_CATALOG: &[DirectProfile] = &[
    DirectProfile { family_id: "a" },
    DirectProfile { family_id: "b" },
    DirectProfile { family_id: "c" },
    DirectProfile { family_id: "d" },
];
EOF

cat > "${FIX1}/aegis-client/src/relay/policy.rs" <<'EOF'
const RELAY_SURFACE_CATALOG: &[RelaySurfaceProfile] = &[
    RelaySurfaceProfile { id: "x" },
    RelaySurfaceProfile { id: "y" },
];
EOF

cat > "${FIX1}/aegis-core/src/config_types.rs" <<'EOF'
fn default_websocket_path_pool() -> Vec<String> {
    vec!["/ws".into()]
}

fn default_grpc_path_pool() -> Vec<String> {
    vec!["/rpc".into()]
}

fn default_masque_path_pool() -> Vec<String> {
    vec!["/masque".into()]
}
EOF

cat > "${FIX1}/aegis-core/src/stealth_rotation.rs" <<'EOF'
const PHASE_SLOT_COUNT: u64 = 17;

pub enum DriftSurface {
    LocalState,
    DirectFingerprint,
    RelaySession,
}
EOF

for name in ttl_desync ip_frag fake_disorder checksum_trick; do
  cat > "${FIX1}/aegis-core/src/strategies/${name}.rs" <<'EOF'
impl Default for X {
    fn default() -> Self {
        Self {
            ttl: 3,
        }
    }
}
EOF
done

touch "${FIX1}/aegis-client/src/runtime_event_stream.rs"

bash "${SCRIPT}" "${TMP_DIR}/out1" --repo-root "${FIX1}" >/dev/null

FIX1_SUMMARY="${TMP_DIR}/out1/stealth-anti-anomaly-acceptance-summary.json"
require_file_contains "${FIX1_SUMMARY}" '"artifact_schema": "stealth_anti_anomaly_acceptance_summary_v1"'
require_file_contains "${FIX1_SUMMARY}" '"verdict": "weak"'
require_file_contains "${FIX1_SUMMARY}" '"composite_anti_anomaly_score": 19'
require_file_contains "${FIX1_SUMMARY}" '"anti_correlation"'
require_file_contains "${FIX1_SUMMARY}" '"score": 38'
require_file_contains "${FIX1_SUMMARY}" '"intra_session_drift"'
require_file_contains "${FIX1_SUMMARY}" '"server_side_coordination"'
require_file_contains "${FIX1_SUMMARY}" '"catalog_diversity"'
require_file_contains "${FIX1_SUMMARY}" '"score": 42'
require_file_contains "${FIX1_SUMMARY}" '"next_action": "open_'

############################################
# Fixture 2: "all improvements landed" — direct=8, relay=6, pools all=3, drift event present, both events, configurable TTL sets
############################################

FIX2="${TMP_DIR}/fix2"
mkdir -p "${FIX2}/aegis-client/src/direct" \
         "${FIX2}/aegis-client/src/relay" \
         "${FIX2}/aegis-client/src" \
         "${FIX2}/aegis-core/src" \
         "${FIX2}/aegis-core/src/strategies" \
         "${FIX2}/aegis-server/src"

cat > "${FIX2}/aegis-client/src/direct/planner.rs" <<'EOF'
const DIRECT_PROFILE_CATALOG: &[DirectProfile] = &[
    DirectProfile { family_id: "a" },
    DirectProfile { family_id: "b" },
    DirectProfile { family_id: "c" },
    DirectProfile { family_id: "d" },
    DirectProfile { family_id: "e" },
    DirectProfile { family_id: "f" },
    DirectProfile { family_id: "g" },
    DirectProfile { family_id: "h" },
];
EOF

cat > "${FIX2}/aegis-client/src/relay/policy.rs" <<'EOF'
const RELAY_SURFACE_CATALOG: &[RelaySurfaceProfile] = &[
    RelaySurfaceProfile { id: "p1" },
    RelaySurfaceProfile { id: "p2" },
    RelaySurfaceProfile { id: "p3" },
    RelaySurfaceProfile { id: "p4" },
    RelaySurfaceProfile { id: "p5" },
    RelaySurfaceProfile { id: "p6" },
];
EOF

cat > "${FIX2}/aegis-core/src/config_types.rs" <<'EOF'
fn default_websocket_path_pool() -> Vec<String> {
    vec!["/ws".into(), "/socket".into(), "/alt".into()]
}

fn default_grpc_path_pool() -> Vec<String> {
    vec!["/rpc1".into(), "/rpc2".into(), "/rpc3".into()]
}

fn default_masque_path_pool() -> Vec<String> {
    vec!["/m1".into(), "/m2".into(), "/m3".into()]
}
EOF

cat > "${FIX2}/aegis-core/src/stealth_rotation.rs" <<'EOF'
const PHASE_SLOT_COUNT: u64 = 17;

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
EOF

# No hardcoded ttl literals in this fixture — strategies use named sets.
for name in ttl_desync ip_frag fake_disorder checksum_trick; do
  cat > "${FIX2}/aegis-core/src/strategies/${name}.rs" <<'EOF'
// TTL now comes from catalog-driven LOW_DECOY_TTL_SET / NORMAL_TTL_SET lookup.
EOF
done

# C4: named TTL sets must be discoverable via ttl_sets.rs for the
# parameter_randomization axis to reach 100.
cat > "${FIX2}/aegis-core/src/strategies/ttl_sets.rs" <<'EOF'
pub const LOW_DECOY_TTL_SET: &[u8] = &[3, 5, 7];
pub const NORMAL_TTL_SET: &[u8] = &[60, 62, 64, 128];
EOF

cat > "${FIX2}/aegis-client/src/runtime_events.rs" <<'EOF'
// "stealth_profile_rotated" emitted after each intra-session drift rotation
// "stealth_profile_negotiated" emitted after server handshake
EOF
cat > "${FIX2}/aegis-client/src/runtime_event_stream.rs" <<'EOF'
// event stream emitter re-emits stealth_profile_rotated on every session close
// when the catalog profile id differs from session-open
EOF

cat > "${FIX2}/aegis-server/src/session.rs" <<'EOF'
// stealth_profile_negotiated produced by server handshake branch
EOF

bash "${SCRIPT}" "${TMP_DIR}/out2" --repo-root "${FIX2}" >/dev/null

FIX2_SUMMARY="${TMP_DIR}/out2/stealth-anti-anomaly-acceptance-summary.json"
require_file_contains "${FIX2_SUMMARY}" '"artifact_schema": "stealth_anti_anomaly_acceptance_summary_v1"'
require_file_contains "${FIX2_SUMMARY}" '"catalog_diversity"'
require_file_contains "${FIX2_SUMMARY}" '"path_pool_coverage"'
require_file_contains "${FIX2_SUMMARY}" '"intra_session_drift"'
require_file_contains "${FIX2_SUMMARY}" '"server_side_coordination"'
require_file_contains "${FIX2_SUMMARY}" '"anti_correlation"'
require_file_contains "${FIX2_SUMMARY}" '"score": 60'
require_file_contains "${FIX2_SUMMARY}" '"parameter_randomization"'
require_file_contains "${FIX2_SUMMARY}" '"LOW_DECOY_TTL_SET"'
require_file_contains "${FIX2_SUMMARY}" '"NORMAL_TTL_SET"'
require_file_contains "${FIX2_SUMMARY}" '"composite_anti_anomaly_score": 93'
require_file_contains "${FIX2_SUMMARY}" '"verdict": "strong"'

############################################
# Fixture 3: real repo sanity — must produce a finite score with a valid verdict
############################################

bash "${SCRIPT}" "${TMP_DIR}/out-real" >/dev/null

REAL_SUMMARY="${TMP_DIR}/out-real/stealth-anti-anomaly-acceptance-summary.json"
require_file_contains "${REAL_SUMMARY}" '"artifact_schema": "stealth_anti_anomaly_acceptance_summary_v1"'
require_file_contains "${REAL_SUMMARY}" '"composite_anti_anomaly_score":'
require_file_contains "${REAL_SUMMARY}" '"verdict":'
require_file_contains "${REAL_SUMMARY}" '"status": "anti_anomaly_'
require_file_contains "${REAL_SUMMARY}" '"next_action": "open_'
require_file_contains "${REAL_SUMMARY}" '"catalog_diversity"'
require_file_contains "${REAL_SUMMARY}" '"parameter_randomization"'
require_file_contains "${REAL_SUMMARY}" '"anti_correlation"'
require_file_contains "${REAL_SUMMARY}" '"intra_session_drift"'
require_file_contains "${REAL_SUMMARY}" '"path_pool_coverage"'
require_file_contains "${REAL_SUMMARY}" '"server_side_coordination"'

echo "build-stealth-anti-anomaly-acceptance-summary contract: ok"
