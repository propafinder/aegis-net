#!/usr/bin/env bash
# The profile itself is refreshed by scripts/refresh-chrome-profile.py.
# This helper still reports the older JA4 and user-agent pins.
#
# Maintenance helper (audit C): re-derive the Chrome mimicry pins from the
# locally installed Chrome and report drift, so the two coupled pins never
# silently diverge from live Chrome:
#
#   1. JA4 pin   — CHROME_JA4C / CHROME_JA4E in
#                  scripts/test-chrome-like-tls-ja4-parity-contract.sh
#   2. UA pin    — CHROME_COHERENT_USER_AGENT in
#                  aegis-client/src/relay/policy.rs
#
# It changes nothing; it prints what to update. Run it on a dev machine with
# Chrome installed after a Chrome major bump (or when the parity contract fails).
# Exits 0 when everything matches, 2 when drift is detected, and SKIPs (0) when
# the environment can't measure — so it is safe to wire into optional CI.
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CAP="${ROOT}/scripts/lib/ja4-clienthello-capture.py"
CONTRACT="${ROOT}/scripts/test-chrome-like-tls-ja4-parity-contract.sh"
POLICY="${ROOT}/aegis-client/src/relay/policy.rs"

command -v python3 >/dev/null || { echo "SKIP: python3 required"; exit 0; }

# Locate a Chrome binary across platforms.
CHROME=""
for cand in \
  "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" \
  "$(command -v google-chrome 2>/dev/null)" \
  "$(command -v google-chrome-stable 2>/dev/null)" \
  "$(command -v chromium 2>/dev/null)"; do
  [[ -n "${cand}" && -x "${cand}" ]] && { CHROME="${cand}"; break; }
done
[[ -n "${CHROME}" ]] || { echo "SKIP: no Chrome/Chromium binary found"; exit 0; }

CHROME_VERSION="$("${CHROME}" --version 2>/dev/null | grep -oE '[0-9]+(\.[0-9]+)*' | head -1)"
CHROME_MAJOR="${CHROME_VERSION%%.*}"
echo "installed Chrome : ${CHROME_VERSION:-unknown}"

# Capture the live Chrome JA4 (the listener closes after the ClientHello; the
# handshake failing is expected and irrelevant to the measurement).
PORT=39931
OUT="$(mktemp)"
python3 "${CAP}" "${PORT}" 15 >"${OUT}" 2>&1 &
PYP=$!
for _ in $(seq 1 25); do grep -q LISTEN "${OUT}" 2>/dev/null && break; sleep 0.2; done
"${CHROME}" --headless=new --disable-gpu --no-first-run --no-default-browser-check \
  "https://127.0.0.1:${PORT}/" >/dev/null 2>&1 &
CHP=$!
for _ in $(seq 1 30); do grep -q JA4C "${OUT}" 2>/dev/null && break; sleep 0.5; done
kill "${PYP}" "${CHP}" >/dev/null 2>&1
LIVE="$(grep -oE 'JA4C=[0-9a-f]+ JA4E=[0-9a-f]+' "${OUT}" | head -1)"
rm -f "${OUT}"
[[ -n "${LIVE}" ]] || { echo "SKIP: could not capture a live Chrome ClientHello"; exit 0; }
LIVE_JA4C="${LIVE#JA4C=}"; LIVE_JA4C="${LIVE_JA4C%% *}"
LIVE_JA4E="${LIVE##*JA4E=}"

PIN_JA4C="$(grep -oE 'CHROME_JA4C="[0-9a-f]+"' "${CONTRACT}" | grep -oE '[0-9a-f]+' | tail -1)"
PIN_JA4E="$(grep -oE 'CHROME_JA4E="[0-9a-f]+"' "${CONTRACT}" | grep -oE '[0-9a-f]+' | tail -1)"
# Scope to the coherent-UA const specifically — the surface catalog elsewhere in
# the file carries its own decoy Chrome/<n> User-Agents we must not read here.
PIN_UA_MAJOR="$(grep -A2 'CHROME_COHERENT_USER_AGENT' "${POLICY}" \
  | grep -oE 'Chrome/[0-9]+' | grep -oE '[0-9]+' | head -1)"

echo "live   JA4      : JA4C=${LIVE_JA4C} JA4E=${LIVE_JA4E}"
echo "pinned JA4      : JA4C=${PIN_JA4C} JA4E=${PIN_JA4E}"
echo "pinned UA major : ${PIN_UA_MAJOR}"

drift=0
if [[ "${LIVE_JA4C}" != "${PIN_JA4C}" || "${LIVE_JA4E}" != "${PIN_JA4E}" ]]; then
  drift=1
  echo
  echo "DRIFT: live Chrome JA4 != pinned JA4. Update ${CONTRACT#"${ROOT}/"}:"
  echo "    CHROME_JA4C=\"${LIVE_JA4C}\""
  echo "    CHROME_JA4E=\"${LIVE_JA4E}\""
  echo "  and re-verify the AWS-LC backend still matches (it may need a"
  echo "  cipher/extension update in aegis-client/src/relay/tls_backend/aws_lc.rs)."
fi
if [[ -n "${CHROME_MAJOR}" && -n "${PIN_UA_MAJOR}" && "${CHROME_MAJOR}" != "${PIN_UA_MAJOR}" ]]; then
  echo
  echo "NOTE: installed Chrome major (${CHROME_MAJOR}) != pinned coherent UA major (${PIN_UA_MAJOR})."
  echo "  Refresh CHROME_COHERENT_USER_AGENT in ${POLICY#"${ROOT}/"} to Chrome/${CHROME_MAJOR}.0.0.0"
  echo "  (an older-but-real UA is not a hard failure — but keep it within a few majors of live)."
fi

if [[ "${drift}" -eq 0 ]]; then
  echo
  echo "OK: live Chrome JA4 matches the pinned JA4."
  exit 0
fi
exit 2
