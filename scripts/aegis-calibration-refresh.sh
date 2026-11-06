#!/usr/bin/env bash
# Rebuild the external calibration summary from a fresh corpus and apply it.
#
# Driven by aegis-calibration-refresh.timer, which ships disabled — the witness
# matrix this depends on puts netem on the live egress interface for minutes.
#
# The one rule here: never apply a summary built from a corpus that is not
# there. A refresh that silently produces an empty summary and applies it is
# worse than no refresh, because the freshness half-life would then keep
# resetting on nothing.
set -euo pipefail

CAL_DIR="${AEGIS_CALIBRATION_DIR:?AEGIS_CALIBRATION_DIR must be set}"
CONFIG="${AEGIS_CLIENT_CONFIG:?AEGIS_CLIENT_CONFIG must be set}"
MEASURE="${AEGIS_MEASURE_BIN:-/usr/local/bin/aegis-measure}"
CLIENT="${AEGIS_CLIENT_BIN:-/usr/local/bin/aegis-client}"
WITNESS="${AEGIS_WITNESS_JSONL:-${CAL_DIR}/witness.jsonl}"
ADVERSARIAL="${AEGIS_ADVERSARIAL_JSONL:-${CAL_DIR}/adversarial.jsonl}"

die() { echo "calibration-refresh: $*" >&2; exit 1; }

[[ -x "${MEASURE}" ]] || die "aegis-measure not found at ${MEASURE}; install it or set AEGIS_MEASURE_BIN"
[[ -x "${CLIENT}" ]]  || die "aegis-client not found at ${CLIENT}"
mkdir -p "${CAL_DIR}"

# A corpus is required. Producing one is a separate, host-specific job (the
# witness matrix harness); this script refuses rather than inventing one.
have_input=0
[[ -s "${WITNESS}" ]] && have_input=1
[[ -s "${ADVERSARIAL}" ]] && have_input=1
[[ "${have_input}" -eq 1 ]] || die "no corpus: neither ${WITNESS} nor ${ADVERSARIAL} has content.
   Point AEGIS_WITNESS_JSONL / AEGIS_ADVERSARIAL_JSONL at a fresh measurement
   run. Refusing to build a summary from nothing — an empty summary would keep
   resetting the freshness half-life and look current forever."

SUMMARY="${CAL_DIR}/external-calibration.json"
TMP="${SUMMARY}.new"

args=(external-calibration-summary --output-json "${TMP}")
[[ -s "${WITNESS}" ]] && args+=(--witness-jsonl "${WITNESS}")
[[ -s "${ADVERSARIAL}" ]] && args+=(--adversarial-jsonl "${ADVERSARIAL}")

"${MEASURE}" "${args[@]}" || die "summary build failed"
[[ -s "${TMP}" ]] || die "summary build produced an empty file"

# Apply before promoting, so a summary the client rejects never becomes the
# stored one.
"${CLIENT}" --config "${CONFIG}" --apply-external-calibration-summary "${TMP}" \
  || die "client rejected the new summary; keeping the previous one"

mv -f "${TMP}" "${SUMMARY}"
echo "calibration-refresh: applied ${SUMMARY}"
