#!/usr/bin/env bash
# Contract test for the release-manifest signature anchor in
# bootstrap-install.sh (Phase 1 critical hardening).
#
# Verifies the ed25519 detached-signature verification semantics that the
# bootstrap fallback path relies on, plus that the enforcement is actually
# wired into bootstrap-install.sh (download .sig -> verify -> abort on
# failure; abort on unsigned manifest unless AEGIS_INSTALL_ALLOW_UNSIGNED=1).

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BOOT="${ROOT}/bootstrap-install.sh"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/aegis-manifest-sig.XXXXXX")"
trap 'rm -rf "${TMP}"' EXIT

fail() { echo "FAIL: $*" >&2; exit 1; }

command -v openssl >/dev/null 2>&1 || fail "openssl required"

# --- keys ---
openssl genpkey -algorithm ed25519 -out "${TMP}/good-key.pem" 2>/dev/null
openssl pkey -in "${TMP}/good-key.pem" -pubout -out "${TMP}/good-pub.pem" 2>/dev/null
openssl genpkey -algorithm ed25519 -out "${TMP}/wrong-key.pem" 2>/dev/null

# --- manifest + signature ---
cat > "${TMP}/release.manifest.json" <<'JSON'
{"schema":"aegis_linux_release_manifest_v1","version":"0.0.0-test","channel":"stable"}
JSON
AEGIS_MANIFEST_SIGNING_KEY="${TMP}/good-key.pem" \
  bash "${ROOT}/scripts/sign-release-manifest.sh" "${TMP}/release.manifest.json" >/dev/null \
  || fail "sign-release-manifest.sh failed on valid input"
[[ -f "${TMP}/release.manifest.json.sig" ]] || fail "signature file not produced"

# Replicate the bootstrap verify_manifest_signature semantics for the
# valid / tampered / wrong-key cases (same openssl invocation).
verify() {
  local manifest="$1" sig="$2" pub="$3"
  openssl pkeyutl -verify -pubin -inkey "${pub}" -rawin -in "${manifest}" -sigfile "${sig}" >/dev/null 2>&1
}

# 1. valid signed manifest accepted
verify "${TMP}/release.manifest.json" "${TMP}/release.manifest.json.sig" "${TMP}/good-pub.pem" \
  || fail "valid signed manifest was NOT accepted"

# 2. tampered manifest rejected (same sig, mutated content)
cp "${TMP}/release.manifest.json" "${TMP}/tampered.json"
echo '{"evil":true}' >> "${TMP}/tampered.json"
if verify "${TMP}/tampered.json" "${TMP}/release.manifest.json.sig" "${TMP}/good-pub.pem"; then
  fail "tampered manifest was accepted (must be rejected)"
fi

# 3. wrong signature rejected (sign with a different key)
openssl pkey -in "${TMP}/wrong-key.pem" -pubout -out "${TMP}/wrong-pub.pem" 2>/dev/null
openssl pkeyutl -sign -inkey "${TMP}/wrong-key.pem" -rawin -in "${TMP}/release.manifest.json" -out "${TMP}/wrong.sig" 2>/dev/null
if verify "${TMP}/release.manifest.json" "${TMP}/wrong.sig" "${TMP}/good-pub.pem"; then
  fail "wrong-key signature was accepted (must be rejected)"
fi

# --- wiring assertions on bootstrap-install.sh ---
grep -q "verify_manifest_signature" "${BOOT}" || fail "bootstrap missing verify_manifest_signature function"
grep -q "MANIFEST_SIG_URL=\"\${MANIFEST_URL}.sig\"" "${BOOT}" || fail "bootstrap does not derive sig URL from resolved manifest URL"
grep -q "signature verification FAILED" "${BOOT}" || fail "bootstrap missing fail-abort on bad signature"
grep -q "AEGIS_INSTALL_ALLOW_UNSIGNED" "${BOOT}" || fail "bootstrap missing explicit unsigned escape-hatch gate"
# The gate must run BEFORE the manifest field parse (python block) so checksums
# are never trusted ahead of the signature.
grep -Fq 'verify_manifest_signature "${candidate_manifest}" "${candidate_sig}"' "${BOOT}" || fail "fallback must verify the same candidate pair"
sig_line=$(grep -n 'if ! download_url_with_fallback "${MANIFEST_PATH}"' "${BOOT}" | head -1 | cut -d: -f1)
parse_line=$(grep -n 'MANIFEST_FIELDS="\$(' "${BOOT}" | head -1 | cut -d: -f1)
[[ -n "${sig_line}" && -n "${parse_line}" && "${sig_line}" -lt "${parse_line}" ]] \
  || fail "signature gate does not precede manifest field parse (sig=${sig_line} parse=${parse_line})"

# 4. unsigned-without-flag must abort: assert the FATAL-no-signature branch exists
grep -q "no manifest signature" "${BOOT}" || fail "bootstrap missing unsigned-manifest abort path"

# 5. pinned pubkey present (verification key, not a private key)
grep -q "AEGIS_MANIFEST_PINNED_PUBKEY" "${BOOT}" || fail "bootstrap missing pinned public key"
if grep -qE "BEGIN (OPENSSH |EC |RSA )?PRIVATE KEY" "${BOOT}"; then
  fail "bootstrap-install.sh contains a PRIVATE KEY (must only embed the public key)"
fi

echo "PASS: manifest signature anchor (valid accept / tampered reject / wrong-key reject / wiring / pubkey-only / gate-before-parse)"
