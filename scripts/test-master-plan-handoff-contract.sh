#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/aegis-master-plan-handoff.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT

mkdir -p "${TMP_DIR}/artifact"
touch \
  "${TMP_DIR}/artifact/phase-b-score-parity-gate.json" \
  "${TMP_DIR}/artifact/phase-c-multi-relay-evidence.json" \
  "${TMP_DIR}/artifact/phase-c-bundle-mirrors-evidence.json"

cat >"${TMP_DIR}/phase-c-fronted-blocked.json" <<'JSON'
{
  "status": "PHASE_C_RESILIENCE_BLOCKED",
  "phase_c_exit_status": "EXIT_NOT_READY",
  "acceptance_degraded": true,
  "blockers": ["cdn_fronted_transport:cdn_fronted_transport_evidence_missing"],
  "artifacts": {
    "phase_b_score_parity_json": "__TMP__/artifact/phase-b-score-parity-gate.json",
    "multi_relay_json": "__TMP__/artifact/phase-c-multi-relay-evidence.json",
    "bundle_mirrors_json": "__TMP__/artifact/phase-c-bundle-mirrors-evidence.json"
  }
}
JSON
sed "s#__TMP__#${TMP_DIR}#g" "${TMP_DIR}/phase-c-fronted-blocked.json" >"${TMP_DIR}/phase-c-fronted-blocked-expanded.json"
cat >"${TMP_DIR}/phase-d-blocked.json" <<'JSON'
{
  "status": "PHASE_D_REACH_BLOCKED",
  "phase_d_exit_status": "EXIT_NOT_READY",
  "acceptance_degraded": true,
  "blockers": [
    "phase_c_resilience_not_ready",
    "windows_reach:service_baseline_missing",
    "macos_reach:network_extension_system_wide_not_proven",
    "android_reach:vpnservice_basic_flow_not_proven"
  ]
}
JSON

bash "${ROOT}/scripts/build-master-plan-handoff.sh" \
  --phase-c-resilience-json "${TMP_DIR}/phase-c-fronted-blocked-expanded.json" \
  --phase-d-reach-json "${TMP_DIR}/phase-d-blocked.json" \
  --artifact-dir "${TMP_DIR}/next" \
  --output-json "${TMP_DIR}/handoff.json" \
  --output-markdown "${TMP_DIR}/handoff.md"

grep -q '"status": "ACTION_REQUIRED"' "${TMP_DIR}/handoff.json"
grep -q '"primary_layer": "phase_c"' "${TMP_DIR}/handoff.json"
grep -q 'run_fronted_provider_preflight_then_two_vps_live' "${TMP_DIR}/handoff.json"
grep -q 'build-phase-c-fronted-provider-preflight.sh' "${TMP_DIR}/handoff.json"
grep -q 'run-phase-c-fronted-transport-two-vps-live.sh' "${TMP_DIR}/handoff.json"
grep -q 'phase-c-fronted-transport-evidence.json' "${TMP_DIR}/handoff.json"
grep -q 'phase-b-score-parity-gate.json' "${TMP_DIR}/handoff.json"
grep -q 'phase-c-multi-relay-evidence.json' "${TMP_DIR}/handoff.json"
grep -q 'phase-c-bundle-mirrors-evidence.json' "${TMP_DIR}/handoff.json"
grep -q '"placeholder": false' "${TMP_DIR}/handoff.json"
grep -q '"exists": true' "${TMP_DIR}/handoff.json"
grep -q '"ready_for_live_command": true' "${TMP_DIR}/handoff.json"
grep -q '"command_placeholder_free": false' "${TMP_DIR}/handoff.json"
grep -q '"followup_command_placeholder_free": false' "${TMP_DIR}/handoff.json"
grep -q '"requires_external_inputs": true' "${TMP_DIR}/handoff.json"
grep -q '"phase_c_fronted_live"' "${TMP_DIR}/handoff.json"
grep -q '"relay_vps"' "${TMP_DIR}/handoff.json"
grep -q '"provider_fronted_authority"' "${TMP_DIR}/handoff.json"
grep -q '"provided_by_repo": false' "${TMP_DIR}/handoff.json"
grep -q 'Phase C follow-up prerequisites ready: `true`' "${TMP_DIR}/handoff.md"
grep -q 'Ready for live command after external inputs: `true`' "${TMP_DIR}/handoff.md"
grep -q 'Command placeholder free: `false`' "${TMP_DIR}/handoff.md"
grep -q 'Follow-up command placeholder free: `false`' "${TMP_DIR}/handoff.md"
grep -q 'External inputs: `' "${TMP_DIR}/handoff.md"
grep -q 'Follow-up command' "${TMP_DIR}/handoff.md"
grep -q 'Master Plan Handoff' "${TMP_DIR}/handoff.md"

cat >"${TMP_DIR}/phase-c-ready.json" <<'JSON'
{
  "status": "PHASE_C_RESILIENCE_READY",
  "phase_c_exit_status": "EXIT_READY",
  "acceptance_degraded": false,
  "blockers": []
}
JSON

bash "${ROOT}/scripts/build-master-plan-handoff.sh" \
  --phase-c-resilience-json "${TMP_DIR}/phase-c-ready.json" \
  --phase-d-reach-json "${TMP_DIR}/phase-d-blocked.json" \
  --artifact-dir "${TMP_DIR}/next" \
  --output-json "${TMP_DIR}/handoff-windows.json"

grep -q '"primary_layer": "phase_d_windows"' "${TMP_DIR}/handoff-windows.json"
grep -q 'run_windows_admin_service_baseline' "${TMP_DIR}/handoff-windows.json"

cat >"${TMP_DIR}/phase-d-desktop-core.json" <<'JSON'
{
  "status": "PHASE_D_PREP_READY",
  "phase_d_exit_status": "EXIT_NOT_READY",
  "phase_d_prep_status": "PREP_READY",
  "acceptance_degraded": true,
  "blockers": [
    "macos_reach:network_extension_system_wide_not_proven",
    "android_reach:vpnservice_basic_flow_not_proven"
  ],
  "windows_reach": {
    "status": "PASS",
    "exit_ready": true
  },
  "macos_reach": {
    "status": "PREP",
    "utun_w4_policy_cleanup_pass": true
  },
  "android_reach": {
    "status": "PREP",
    "overstated_claim_detected": false
  }
}
JSON

bash "${ROOT}/scripts/build-master-plan-handoff.sh" \
  --phase-c-resilience-json "${TMP_DIR}/phase-c-ready.json" \
  --phase-d-reach-json "${TMP_DIR}/phase-d-desktop-core.json" \
  --artifact-dir "${TMP_DIR}/next" \
  --output-json "${TMP_DIR}/handoff-desktop-core.json"

grep -q '"primary_layer": "desktop_core"' "${TMP_DIR}/handoff-desktop-core.json"
grep -q 'macos_utun_w5_controlled_external_relay_path' "${TMP_DIR}/handoff-desktop-core.json"
grep -q 'Brain external-calibration runtime proof is now the completed prerequisite' "${TMP_DIR}/handoff-desktop-core.json"
grep -q 'DEFERRED_OPTIONAL_PLATFORM_REACH' "${TMP_DIR}/handoff-desktop-core.json"
grep -q 'EXTERNALLY_BLOCKED' "${TMP_DIR}/handoff-desktop-core.json"
if grep -q 'run_android_vpnservice_basic_flow_proof' "${TMP_DIR}/handoff-desktop-core.json"; then
  echo "expected Android to be deferred in desktop/core handoff" >&2
  exit 1
fi

cat >"${TMP_DIR}/phase-d-current-mvp.json" <<'JSON'
{
  "status": "PHASE_D_PREP_READY",
  "phase_d_exit_status": "EXIT_NOT_READY",
  "phase_d_prep_status": "PREP_READY",
  "acceptance_degraded": true,
  "blockers": [
    "macos_reach:network_extension_system_wide_not_proven",
    "android_reach:vpnservice_basic_flow_not_proven"
  ],
  "windows_reach": {
    "status": "PASS",
    "exit_ready": true,
    "service_reboot_pass": true,
    "dns_udp_next_scope_status": "UDP_CAPTURE_REQUIRES_NEW_WFP_LAYER"
  },
  "macos_reach": {
    "status": "PREP",
    "utun_w4_policy_cleanup_pass": true,
    "utun_w5_controlled_external_relay_path_pass": true
  },
  "android_reach": {
    "status": "PREP",
    "overstated_claim_detected": false
  }
}
JSON

bash "${ROOT}/scripts/build-master-plan-handoff.sh" \
  --phase-c-resilience-json "${TMP_DIR}/phase-c-ready.json" \
  --phase-d-reach-json "${TMP_DIR}/phase-d-current-mvp.json" \
  --artifact-dir "${TMP_DIR}/next" \
  --output-json "${TMP_DIR}/handoff-before-release-parity.json"

grep -q 'release_latest_parity' "${TMP_DIR}/handoff-before-release-parity.json"

mkdir -p "${TMP_DIR}/release-latest-parity-gate"
cat >"${TMP_DIR}/release-latest-parity-gate/result.json" <<'JSON'
{
  "verdict": "PASS",
  "status": "RELEASE_LATEST_PARITY_READY"
}
JSON

bash "${ROOT}/scripts/build-master-plan-handoff.sh" \
  --phase-c-resilience-json "${TMP_DIR}/phase-c-ready.json" \
  --phase-d-reach-json "${TMP_DIR}/phase-d-current-mvp.json" \
  --artifact-dir "${TMP_DIR}/next" \
  --output-json "${TMP_DIR}/handoff-after-release-parity.json"

grep -q 'ubuntu_wide_tproxy_latest_stable_release_proof' "${TMP_DIR}/handoff-after-release-parity.json"
grep -q 'Ubuntu wide latest/stable' "${TMP_DIR}/handoff-after-release-parity.json"
grep -q '"ubuntu_wide_latest_stable": "REQUIRED_NEXT"' "${TMP_DIR}/handoff-after-release-parity.json"
grep -q '"full_mimicry_score_matrix": "REQUIRED_NEXT"' "${TMP_DIR}/handoff-after-release-parity.json"
grep -q '"brain_operational_loop": "REQUIRED_NEXT"' "${TMP_DIR}/handoff-after-release-parity.json"
grep -q '"android": "DEFERRED"' "${TMP_DIR}/handoff-after-release-parity.json"
grep -q '"macos_networkextension": "EXTERNALLY_BLOCKED"' "${TMP_DIR}/handoff-after-release-parity.json"
if grep -q '"id": "release_latest_parity"' "${TMP_DIR}/handoff-after-release-parity.json"; then
  echo "expected release/latest parity PASS to move handoff past release_latest_parity" >&2
  exit 1
fi

mkdir -p \
  "${TMP_DIR}/ubuntu-wide-tproxy-latest-stable-release-live" \
  "${TMP_DIR}/mimicry-http-like-witness-matrix" \
  "${TMP_DIR}/brain-operational-live-calibrated-transport-proof" \
  "${TMP_DIR}/adverse-cloudflare-reference-observer-blocker"
cat >"${TMP_DIR}/ubuntu-wide-tproxy-latest-stable-release-live/result.json" <<'JSON'
{
  "verdict": "PASS",
  "status": "PASS"
}
JSON
cat >"${TMP_DIR}/mimicry-http-like-witness-matrix/result.json" <<'JSON'
{
  "verdict": "SCOPED_PASS_REFERENCE_READY",
  "status": "SCOPED_PASS_REFERENCE_READY"
}
JSON
cat >"${TMP_DIR}/brain-operational-live-calibrated-transport-proof/result.json" <<'JSON'
{
  "verdict": "PASS",
  "status": "PASS"
}
JSON
cat >"${TMP_DIR}/adverse-cloudflare-reference-observer-blocker/result.json" <<'JSON'
{
  "verdict": "BLOCKED",
  "status": "BLOCKED_CLIENT_OBSERVER_UNAVAILABLE"
}
JSON

bash "${ROOT}/scripts/build-master-plan-handoff.sh" \
  --phase-c-resilience-json "${TMP_DIR}/phase-c-ready.json" \
  --phase-d-reach-json "${TMP_DIR}/phase-d-current-mvp.json" \
  --artifact-dir "${TMP_DIR}/next" \
  --output-json "${TMP_DIR}/handoff-adverse-observer-blocked.json"

grep -q 'provision_client_observer_vps_for_adverse_reference' "${TMP_DIR}/handoff-adverse-observer-blocked.json"
grep -Fq '<reference-origin-address>' "${TMP_DIR}/handoff-adverse-observer-blocked.json"
grep -Fq '<reference-authority>' "${TMP_DIR}/handoff-adverse-observer-blocked.json"
grep -q '"command_placeholder_free": false' "${TMP_DIR}/handoff-adverse-observer-blocked.json"
grep -q '"requires_external_inputs": true' "${TMP_DIR}/handoff-adverse-observer-blocked.json"
grep -q '"brain_operational_loop": "PASS"' "${TMP_DIR}/handoff-adverse-observer-blocked.json"
grep -q '"full_mimicry_score_matrix": "REQUIRED_NEXT"' "${TMP_DIR}/handoff-adverse-observer-blocked.json"
if grep -qi 'origin-side-only substitution' "${TMP_DIR}/handoff-adverse-observer-blocked.json"; then
  true
else
  echo "expected handoff to reject origin-side-only substitution" >&2
  exit 1
fi

mkdir -p "${TMP_DIR}/adverse-cloudflare-reference-profiles"
cat >"${TMP_DIR}/adverse-cloudflare-reference-profiles/result.json" <<'JSON'
{
  "verdict": "SCOPED_REFERENCE_READY",
  "status": "SCOPED_ADVERSE_REFERENCE_CAPTURED"
}
JSON

bash "${ROOT}/scripts/build-master-plan-handoff.sh" \
  --phase-c-resilience-json "${TMP_DIR}/phase-c-ready.json" \
  --phase-d-reach-json "${TMP_DIR}/phase-d-current-mvp.json" \
  --artifact-dir "${TMP_DIR}/next" \
  --output-json "${TMP_DIR}/handoff-adverse-reference-ready.json"

grep -q 'compare_adverse_reference_profiles_against_mimicry_witness_matrix' "${TMP_DIR}/handoff-adverse-reference-ready.json"
grep -q 'adverse-cloudflare-reference-profiles/result.json' "${TMP_DIR}/handoff-adverse-reference-ready.json"
grep -q '"brain_operational_loop": "PASS"' "${TMP_DIR}/handoff-adverse-reference-ready.json"
grep -q '"full_mimicry_score_matrix": "REQUIRED_NEXT"' "${TMP_DIR}/handoff-adverse-reference-ready.json"

mkdir -p "${TMP_DIR}/mimicry-adverse-reference-comparison"
cat >"${TMP_DIR}/mimicry-adverse-reference-comparison/result.json" <<'JSON'
{
  "verdict": "PARTIAL",
  "status": "PARTIAL_ADVERSE_REFERENCE_COMPARISON_MISMATCH"
}
JSON

bash "${ROOT}/scripts/build-master-plan-handoff.sh" \
  --phase-c-resilience-json "${TMP_DIR}/phase-c-ready.json" \
  --phase-d-reach-json "${TMP_DIR}/phase-d-current-mvp.json" \
  --artifact-dir "${TMP_DIR}/next" \
  --output-json "${TMP_DIR}/handoff-adverse-reference-compared.json"

grep -q 'harden_http_like_tls_fingerprint_and_shape_against_adverse_reference' "${TMP_DIR}/handoff-adverse-reference-compared.json"
grep -q 'mimicry-adverse-reference-comparison/result.json' "${TMP_DIR}/handoff-adverse-reference-compared.json"
grep -q 'JA3/JA4' "${TMP_DIR}/handoff-adverse-reference-compared.json"
grep -q '"full_mimicry_score_matrix": "REQUIRED_NEXT"' "${TMP_DIR}/handoff-adverse-reference-compared.json"

cat >"${TMP_DIR}/phase-d-ready.json" <<'JSON'
{
  "status": "PHASE_D_EXIT_READY",
  "phase_d_exit_status": "EXIT_READY",
  "acceptance_degraded": false,
  "blockers": []
}
JSON

bash "${ROOT}/scripts/build-master-plan-handoff.sh" \
  --phase-c-resilience-json "${TMP_DIR}/phase-c-ready.json" \
  --phase-d-reach-json "${TMP_DIR}/phase-d-ready.json" \
  --artifact-dir "${TMP_DIR}/next" \
  --output-json "${TMP_DIR}/handoff-ready.json"

grep -q '"status": "READY_FOR_NEXT_PHASE"' "${TMP_DIR}/handoff-ready.json"
grep -q 'open_next_master_plan_phase' "${TMP_DIR}/handoff-ready.json"

echo "ok"
