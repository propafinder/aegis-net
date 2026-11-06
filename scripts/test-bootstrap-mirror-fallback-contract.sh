#!/usr/bin/env bash
# Contract: bootstrap-install.sh's multi-provider mirror fallback actually
# works — when the primary source is unreachable, download_url_with_fallback
# selects a configured mirror. Proves the multi-provider DELIVERY MECHANISM
# (threat-model row 7) functionally, using file:// sources (no network).
#
# Note: this proves the MECHANISM. Making bootstrap non-Cloudflare-heavy in
# PRODUCTION additionally requires a LIVE non-Cloudflare mirror endpoint, which
# is an infra/deployment decision, not code.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SRC="$ROOT/bootstrap-install.sh"
fail() { echo "CONTRACT FAIL: $1" >&2; exit 1; }
[ -f "$SRC" ] || fail "missing bootstrap-install.sh"

WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
# Extract the three functions we exercise (self-contained, no side effects).
extract() { awk "/^$1\\(\\) \\{/,/^\\}/" "$SRC"; }
{
  extract has_command
  extract validate_release_policy
  extract release_floor_run
  extract verify_manifest_signature
  extract download_url
  extract download_url_with_fallback
} > "$WORK/fns.sh"
# shellcheck disable=SC1090
MANIFEST_URL_RESOLVED_BY_FALLBACK=""
source "$WORK/fns.sh"
AEGIS_ALLOW_UNSIGNED_MANIFEST=0
AEGIS_MANIFEST_PUBKEY_PEM="$WORK/fixture.pub"
openssl genpkey -algorithm ed25519 -out "$WORK/fixture.key" 2>/dev/null
openssl pkey -in "$WORK/fixture.key" -pubout -out "${AEGIS_MANIFEST_PUBKEY_PEM}" 2>/dev/null

# Real mirror content; primary points at a nonexistent file.
echo '{"ok":true,"from":"mirror"}' > "$WORK/mirror.json"
openssl pkeyutl -sign -inkey "$WORK/fixture.key" -rawin -in "$WORK/mirror.json" -out "$WORK/mirror.json.sig"
REQUIRE_RELEASE_POLICY=0
ALLOW_HISTORICAL_POLICY=1
HISTORICAL_MANIFEST_SHA256="$(shasum -a 256 "$WORK/mirror.json" | cut -d ' ' -f1)"
HISTORICAL_SIGNATURE_SHA256="$(shasum -a 256 "$WORK/mirror.json.sig" | cut -d ' ' -f1)"
HOME="${WORK}/fixture-user"
AEGIS_HOST_ARCH=x86_64
PRIMARY="file://$WORK/does-not-exist-primary.json"
MIRROR="file://$WORK/mirror.json"
DEST="$WORK/out.json"

download_url_with_fallback "$DEST" "$PRIMARY" "$MIRROR" >/dev/null 2>&1 || fail "fallback returned nonzero"
[ -s "$DEST" ] || fail "no file downloaded"
grep -q '"from":"mirror"' "$DEST" || fail "downloaded content is not the mirror's"
[ "$MANIFEST_URL_RESOLVED_BY_FALLBACK" = "$MIRROR" ] || fail "fallback did not record the mirror as resolver (got: $MANIFEST_URL_RESOLVED_BY_FALLBACK)"

# Negative: all-unreachable must fail closed.
if download_url_with_fallback "$WORK/out2.json" "file://$WORK/none-a" "file://$WORK/none-b" >/dev/null 2>&1; then
  fail "fallback should fail when all sources are unreachable"
fi
echo "bootstrap-mirror-fallback-contract: PASS (primary down -> mirror selected; all-down -> fail-closed)"
