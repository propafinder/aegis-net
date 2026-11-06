#!/usr/bin/env bash
# Contract: the active-probing decoy artifacts are well-formed, claim no
# more than SCOPED_PASS, and contain no secrets.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DIR="$ROOT/scripts/tests/fixtures/evidence/live/2026-06-09"
fail() { echo "CONTRACT FAIL: $1" >&2; exit 1; }
for f in active-probing-code-audit/result.json active-probing-decoy-corpus/result.json active-probing-decoy-corpus/after-patched-binary.json; do
  p="$DIR/$f"; [ -f "$p" ] || fail "missing $f"
  python3 -m json.tool "$p" >/dev/null || fail "invalid JSON $f"
done
# no overclaim
if grep -riE 'undetectable|perfect (stealth|mimicry)|browser-identical(?!.*not)|universal (anti-dpi|bypass)|fully indistinguishable|nation-state proof' "$DIR"/active-probing-* 2>/dev/null | grep -vi 'not_claimed\|not claimed\|NOT browser\|not proven'; then
  fail "overclaim string in active-probing artifacts"
fi
# decoy verdict must be present and bounded
grep -q 'SCOPED_PASS' "$DIR/active-probing-decoy-corpus/after-patched-binary.json" || fail "after-corpus missing SCOPED_PASS verdict"
grep -q 'NOT browser/REALITY' "$DIR/active-probing-decoy-corpus/after-patched-binary.json" || fail "after-corpus missing scope caveat"
# no secrets
if grep -rIE 'BEGIN .*PRIVATE KEY|auth_token *= *"[0-9a-f]{16}|cfat_|CF_API_TOKEN' "$DIR"/active-probing-* 2>/dev/null; then
  fail "secret-like string in artifacts"
fi
echo "active-probing-decoy-contract: PASS"
