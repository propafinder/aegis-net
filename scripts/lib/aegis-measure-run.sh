#!/bin/bash
# Run aegis-measure with a bounded wall-clock timeout.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TIMEOUT_SECONDS="${AEGIS_MEASURE_TIMEOUT_SECONDS:-20}"

if [[ ! "${TIMEOUT_SECONDS}" =~ ^[0-9]+$ || "${TIMEOUT_SECONDS}" -lt 1 ]]; then
  echo "AEGIS_MEASURE_TIMEOUT_SECONDS must be a positive integer" >&2
  exit 2
fi

if command -v timeout >/dev/null 2>&1; then
  exec timeout "${TIMEOUT_SECONDS}s" cargo run -q -p aegis-measure -- "$@"
fi
if command -v gtimeout >/dev/null 2>&1; then
  exec gtimeout "${TIMEOUT_SECONDS}s" cargo run -q -p aegis-measure -- "$@"
fi

cargo run -q -p aegis-measure -- "$@" &
cmd_pid="$!"
timeout_marker="$(mktemp "${TMPDIR:-/tmp}/aegis-measure-timeout.XXXXXX")"
rm -f "${timeout_marker}"

(
  sleep "${TIMEOUT_SECONDS}"
  if kill -0 "${cmd_pid}" >/dev/null 2>&1; then
    : >"${timeout_marker}"
    echo "aegis-measure timed out after ${TIMEOUT_SECONDS}s" >&2
    pkill -TERM -P "${cmd_pid}" >/dev/null 2>&1 || true
    kill -TERM "${cmd_pid}" >/dev/null 2>&1 || true
    sleep 2
    pkill -KILL -P "${cmd_pid}" >/dev/null 2>&1 || true
    kill -KILL "${cmd_pid}" >/dev/null 2>&1 || true
  fi
) &
watchdog_pid="$!"

set +e
wait "${cmd_pid}"
status="$?"
set -e

kill "${watchdog_pid}" >/dev/null 2>&1 || true
wait "${watchdog_pid}" 2>/dev/null || true
if [[ -f "${timeout_marker}" ]]; then
  rm -f "${timeout_marker}"
  exit 124
fi
rm -f "${timeout_marker}"
exit "${status}"
