#!/usr/bin/env bash
# Inert source contract: failed route observation cannot yield a passing soak.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
mkdir "$TMP/bin"
cat > "$TMP/bin/curl" <<'CURL'
#!/bin/sh
if [ -n "${MOCK_CURL_LOG:-}" ]; then printf 'request\n' >> "$MOCK_CURL_LOG"; fi
case "$*" in *time_total*) printf '200 0.01';; *) printf '200';; esac
CURL
cat > "$TMP/bin/ip" <<'IP'
#!/bin/sh
case "${MOCK_IP_MODE:-}" in
  fail) exit 42;;
  residual)
    case "$*" in *route*) printf 'default dev aegis-tun0\n';; *link*) printf '1: aegis-tun0: <UP>\n';; esac;;
esac
IP
cat > "$TMP/bin/systemctl" <<'SYSTEMCTL'
#!/bin/sh
if [ "${MOCK_IP_MODE:-}" = goodunit ]; then printf '0\n'; exit 0; fi
exit 42
SYSTEMCTL
cat > "$TMP/bin/date" <<'DATE'
#!/bin/sh
if [ "${MOCK_DATE_BOUNDARY:-}" = 1 ] && [ "$1" = '+%s' ]; then
  if [ ! -e "$MOCK_DATE_STATE" ]; then
    : > "$MOCK_DATE_STATE"
    printf '1000\n'
  else
    printf '1001\n'
  fi
else
  /bin/date "$@"
fi
DATE
chmod +x "$TMP/bin/curl" "$TMP/bin/ip" "$TMP/bin/date" "$TMP/bin/systemctl"
run_case() {
  local mode="$1"
  local watch_unit="${2:-}"
  local out="$TMP/$mode.json"
  local -a watch_args=()
  if [[ -n "$watch_unit" ]]; then watch_args=(--watch-unit "$watch_unit"); fi
  MOCK_IP_MODE="$mode" PATH="$TMP/bin:$PATH" bash "$ROOT/scripts/soak-linux-operator-modes.sh" \
    --duration 1 --interval 1 --direct --target http://127.0.0.1/ --out "$out" \
    "${watch_args[@]}" \
    >"$TMP/$mode.stdout" 2>"$TMP/$mode.stderr"
}
# A previous success must be untouched and the new attempt must refuse before
# issuing even one request. This also covers the constant default report path.
printf 'previous-pass\n' > "$TMP/stale.json"
if MOCK_CURL_LOG="$TMP/stale-requests.log" run_case stale; then
  echo 'FAIL: existing report path accepted' >&2
  exit 1
fi
[[ "$(cat "$TMP/stale.json")" == 'previous-pass' ]] || { echo 'FAIL: prior receipt changed' >&2; exit 1; }
[[ ! -e "$TMP/stale-requests.log" ]] || { echo 'FAIL: request issued before output refusal' >&2; exit 1; }
ln -s "$TMP/missing.json" "$TMP/link.json"
if run_case link; then
  echo 'FAIL: dangling symlink report path accepted' >&2
  exit 1
fi
[[ ! -e "$TMP/missing.json" ]] || { echo 'FAIL: wrote through report symlink' >&2; exit 1; }
if run_case fail; then
  echo 'FAIL: failed route observer yielded exit 0' >&2
  exit 1
fi
[[ ! -e "$TMP/fail.json" ]] || { echo 'FAIL: failed observer wrote a report' >&2; exit 1; }
if run_case failunit aegis-test.service; then
  echo 'FAIL: failed explicit unit observer yielded exit 0' >&2
  exit 1
fi
[[ ! -e "$TMP/failunit.json" ]] || { echo 'FAIL: failed unit observer wrote a report' >&2; exit 1; }
run_case goodunit aegis-test.service
run_case clear
# Force the wall clock to cross the deadline between initialization and the
# first loop condition; a one-second soak must still issue one request.
if ! MOCK_DATE_BOUNDARY=1 MOCK_DATE_STATE="$TMP/boundary-date.state" run_case boundary; then
  echo 'FAIL: one-second boundary produced no passing request' >&2
  exit 1
fi
python3 - "$TMP/boundary.json" <<'PY'
import json, sys
r = json.load(open(sys.argv[1]))['results']
assert r['requests_total'] == r['requests_ok'] == 1
PY
python3 - "$TMP/clear.json" <<'PY'
import json, sys
r = json.load(open(sys.argv[1]))['results']
assert r['route_residual_routes'] == r['route_residual_ifaces'] == 0
PY
# An actual prior PASS is immutable when the same path is reused.
clear_sha="$(shasum -a 256 "$TMP/clear.json" | awk '{print $1}')"
if MOCK_CURL_LOG="$TMP/retry-requests.log" run_case clear; then
  echo 'FAIL: prior PASS report path accepted' >&2
  exit 1
fi
[[ "$(shasum -a 256 "$TMP/clear.json" | awk '{print $1}')" == "$clear_sha" ]] \
  || { echo 'FAIL: prior PASS report changed' >&2; exit 1; }
[[ ! -e "$TMP/retry-requests.log" ]] || { echo 'FAIL: retry issued a request' >&2; exit 1; }
ln "$TMP/clear.json" "$TMP/hardlink.json"
if run_case hardlink; then
  echo 'FAIL: hardlinked report path accepted' >&2
  exit 1
fi
[[ "$(shasum -a 256 "$TMP/clear.json" | awk '{print $1}')" == "$clear_sha" ]] \
  || { echo 'FAIL: hardlinked prior PASS changed' >&2; exit 1; }
# The default output filename also needs a fresh path for each attempt.
mkdir "$TMP/default"
(
  cd "$TMP/default"
  PATH="$TMP/bin:$PATH" bash "$ROOT/scripts/soak-linux-operator-modes.sh" \
    --duration 1 --interval 1 --direct --target http://127.0.0.1/ >/dev/null
)
default_sha="$(shasum -a 256 "$TMP/default/soak-result.json" | awk '{print $1}')"
if (
  cd "$TMP/default"
  MOCK_CURL_LOG="$TMP/default-retry-requests.log" PATH="$TMP/bin:$PATH" \
    bash "$ROOT/scripts/soak-linux-operator-modes.sh" \
    --duration 1 --interval 1 --direct --target http://127.0.0.1/ \
    >"$TMP/default-retry.stdout" 2>"$TMP/default-retry.stderr"
); then
  echo 'FAIL: reused default report path accepted' >&2
  exit 1
fi
[[ "$(shasum -a 256 "$TMP/default/soak-result.json" | awk '{print $1}')" == "$default_sha" ]] \
  || { echo 'FAIL: default prior PASS changed' >&2; exit 1; }
[[ ! -e "$TMP/default-retry-requests.log" ]] || { echo 'FAIL: default retry issued a request' >&2; exit 1; }
if run_case residual; then
  echo 'FAIL: residual route/interface yielded exit 0' >&2
  exit 1
fi
python3 - "$TMP/residual.json" <<'PY'
import json, sys
r = json.load(open(sys.argv[1]))['results']
assert r['route_residual_routes'] == r['route_residual_ifaces'] == 1
PY
printf 'PASS: unique output, route observer failure, clean state, and residual state\n'
