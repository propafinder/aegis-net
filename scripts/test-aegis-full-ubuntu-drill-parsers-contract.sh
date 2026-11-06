#!/usr/bin/env bash
# Contract test for the awk-based JSONL parsers used by
# scripts/aegis-full-ubuntu-live-drill.sh.
#
# Replaces the previous python3 dependency (banned by the AEGIS
# Rust+Bash-only orchestration rule). Verifies that:
#
# 1. The transport-extraction awk used by the transport_matrix lane
#    correctly pulls the PascalCase value of "transport":"..." from
#    relay_transport_selected / relay_session_succeeded events.
#
# 2. The target/port histogram awk used by the tproxy_gateway lane
#    produces a `count (target,port)` histogram with the most common
#    entries first.

set -euo pipefail

TMPDIR="$(mktemp -d "${TMPDIR:-/tmp}/aegis-drill-parsers.XXXXXX")"
trap 'rm -rf "${TMPDIR}"' EXIT

JSONL="${TMPDIR}/runtime-events.jsonl"

# --- synthetic JSONL (mirrors real aegis-client runtime-events shape) -----

cat > "${JSONL}" <<'EOF'
{"ts_unix_ms":1,"level":"info","event_code":"relay_transport_selected","fields":{"transport":"HttpsWs","target":"1.1.1.1","port":443}}
{"ts_unix_ms":2,"level":"info","event_code":"relay_session_succeeded","fields":{"transport":"HttpsWs","target":"1.1.1.1","port":443}}
{"ts_unix_ms":3,"level":"info","event_code":"relay_transport_selected","fields":{"transport":"GrpcStream","target":"1.1.1.1","port":443}}
{"ts_unix_ms":4,"level":"info","event_code":"relay_session_succeeded","fields":{"transport":"GrpcStream","target":"1.1.1.1","port":443}}
{"ts_unix_ms":5,"level":"info","event_code":"relay_session_started","fields":{"target":"198.51.100.197","port":445}}
{"ts_unix_ms":6,"level":"info","event_code":"relay_session_started","fields":{"target":"198.51.100.197","port":445}}
{"ts_unix_ms":7,"level":"info","event_code":"relay_session_started","fields":{"target":"198.51.100.197","port":23}}
{"ts_unix_ms":8,"level":"info","event_code":"relay_session_started","fields":{"target":"1.1.1.1","port":443}}
{"ts_unix_ms":9,"level":"info","event_code":"relay_session_started","fields":{"target":"198.51.100.197","port":445}}
{"ts_unix_ms":10,"level":"info","event_code":"relay_transport_selected","fields":{"transport":"MasqueDerived","target":"1.1.1.1","port":443}}
{"ts_unix_ms":11,"level":"info","event_code":"relay_transport_selected","fields":{"transport":"LegacyTls","target":"1.1.1.1","port":443}}
EOF

# --- test 1: transport extraction (transport_matrix lane awk) -------------

extracted="$(grep -E 'relay_transport_selected|relay_session_succeeded' "${JSONL}" \
    | awk 'match($0, /"transport":"[^"]*"/) {
              s = substr($0, RSTART+13, RLENGTH-14); print s
           }' \
    | sort -u)"

for expected in HttpsWs GrpcStream MasqueDerived LegacyTls; do
    if ! echo "${extracted}" | grep -qx "${expected}"; then
        echo "FAIL: transport extraction missed ${expected}; got:" >&2
        echo "${extracted}" >&2
        exit 1
    fi
done
count="$(echo "${extracted}" | wc -l)"
[[ "${count}" -eq 4 ]] || {
    echo "FAIL: expected 4 unique transports, got ${count}: ${extracted}" >&2
    exit 1
}

# --- test 2: target/port histogram (tproxy_gateway lane awk) --------------

histogram="$(grep "relay_session_started" "${JSONL}" \
    | awk '
        {
            t=""; p="";
            if (match($0, /"target":"[^"]*"/)) {
                t = substr($0, RSTART+10, RLENGTH-11)
            }
            if (match($0, /"port":[0-9]+/)) {
                p = substr($0, RSTART+7, RLENGTH-7)
            }
            if (t != "" || p != "") print "("t"," p")"
        }
    ' | sort | uniq -c | sort -rn)"

# Top row should be the scan-noise target with port 445 (3 hits in synthetic data).
top="$(echo "${histogram}" | head -1)"
echo "${top}" | grep -q '198.51.100.197' && echo "${top}" | grep -q '445' || {
    echo "FAIL: top histogram row should be (198.51.100.197, 445); got: ${top}" >&2
    echo "full histogram:" >&2
    echo "${histogram}" >&2
    exit 1
}

# Histogram should contain exactly 3 distinct (target,port) pairs.
distinct="$(echo "${histogram}" | wc -l)"
[[ "${distinct}" -eq 3 ]] || {
    echo "FAIL: expected 3 distinct (target,port) pairs, got ${distinct}:" >&2
    echo "${histogram}" >&2
    exit 1
}

# Real test target (1.1.1.1, 443) must appear in the histogram.
echo "${histogram}" | grep -q '1.1.1.1' || {
    echo "FAIL: histogram missing real test target 1.1.1.1" >&2
    exit 1
}

# --- test 3: orchestrator must not invoke python3 anymore ----------------

# Strip comment lines first, then look for actual python invocations
# (binary calls / shebang / heredoc piped into python). Mere mentions
# of "python" in commentary are fine.
drill_script="$(dirname "$0")/aegis-full-ubuntu-live-drill.sh"
non_comment="$(sed 's/#.*$//' "${drill_script}")"
if echo "${non_comment}" | grep -nE 'python3?[[:space:]]+-c|\|[[:space:]]*python3?|[[:space:]]python3?[[:space:]]' \
   | head -1; then
    echo "FAIL: aegis-full-ubuntu-live-drill.sh still invokes python — violates Rust+Bash-only rule" >&2
    exit 1
fi

echo "PASS: drill parser awks + Rust+Bash-only orchestration contract"
