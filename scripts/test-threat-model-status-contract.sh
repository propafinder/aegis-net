#!/usr/bin/env bash
# Contract: the RKN/TSPU threat model uses the honest status vocabulary and
# never claims universal bypass or browser-identical TLS.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
D="$ROOT/docs/threat-model-rkn-tspu.md"
fail() { echo "CONTRACT FAIL: $1" >&2; exit 1; }
[ -f "$D" ] || fail "missing threat-model doc"
grep -q 'NOT_PROVEN' "$D" || fail "must mark browser-parity NOT_PROVEN"
grep -q 'SCOPED_PASS' "$D" || fail "active probing must be SCOPED_PASS, not PASS"
grep -qiE 'not.{0,8}universal' "$D" || fail "must disclaim universal bypass"
# forbid bare overclaims outside disclaimer lines
if grep -inE 'browser-identical|universal bypass|undetectable' "$D" | grep -viE '\bnot\b|NOT_|disclaim|never'; then
  fail "overclaim in threat model"
fi
echo "threat-model-status-contract: PASS"
