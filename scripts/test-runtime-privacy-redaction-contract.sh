#!/usr/bin/env bash
# Contract: runtime-evidence privacy audit is honest (PARTIAL), records the
# no-log switch, and asserts no auth/bundle secret is logged by events.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
P="$ROOT/scripts/tests/fixtures/evidence/live/2026-06-09/runtime-evidence-privacy-audit/result.json"
fail() { echo "CONTRACT FAIL: $1" >&2; exit 1; }
[ -f "$P" ] || fail "missing privacy audit"
python3 -m json.tool "$P" >/dev/null || fail "invalid JSON"
grep -q 'PRIVACY_MODE_PARTIAL' "$P" || fail "privacy verdict must be PARTIAL (not overclaimed)"
grep -q 'no-runtime-events' "$P" || fail "must record the --no-runtime-events switch"
# code-truth: no secret field names in the event structs
if grep -niE 'auth_token|bundle.?token' "$ROOT/aegis-client/src/runtime_events.rs" 2>/dev/null | grep -vi 'comment\|//'; then
  fail "runtime_events.rs appears to reference a secret field — re-audit"
fi
echo "runtime-privacy-redaction-contract: PASS"
