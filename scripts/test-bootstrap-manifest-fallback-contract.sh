#!/usr/bin/env bash
# Phase 5.0.D contract: bootstrap-install.sh must iterate through
# `AEGIS_INSTALL_MIRRORS` when the primary `AEGIS_INSTALL_MANIFEST_URL`
# is unreachable, and record the URL that actually delivered the
# manifest into MANIFEST_URL_RESOLVED_BY_FALLBACK.
#
# We test the helper directly (not a full install). The bootstrap
# script's top-level body runs argument parsing + manifest download,
# so we extract just the two functions we exercise (`download_url`
# and `download_url_with_fallback`) and replay them against
# `file://` URLs in a temp dir.
#
# Runs offline. No real network. The "blocked primary" case is
# simulated by pointing at a non-existent file.

set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="${ROOT}/bootstrap-install.sh"

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

extracted_helpers="$(mktemp -d)"/bootstrap-helpers.sh
tmpdir="$(mktemp -d)"
trap 'rm -rf "$(dirname "${extracted_helpers}")" "${tmpdir}"' EXIT

# Pull only the helper functions out — same brace-counting approach as
# the install.sh test. The functions live near the top, before the
# script's main flow runs anything that touches the filesystem.
awk '
  /^has_command\(\) \{/ ||
  /^validate_release_policy\(\) \{/ ||
  /^release_floor_run\(\) \{/ ||
  /^verify_manifest_signature\(\) \{/ ||
  /^download_url\(\) \{/ ||
  /^download_url_with_fallback\(\) \{/ {
    in_fn = 1; brace = 0
  }
  in_fn {
    print
    n = gsub(/\{/, "{")
    brace += n
    n = gsub(/\}/, "}")
    brace -= n
    if (brace == 0 && /^\}/) { in_fn = 0 }
  }
' "${SCRIPT}" > "${extracted_helpers}"

MANIFEST_URL_RESOLVED_BY_FALLBACK=""
# shellcheck disable=SC1090
. "${extracted_helpers}"
AEGIS_ALLOW_UNSIGNED_MANIFEST=0
AEGIS_MANIFEST_PUBKEY_PEM="${tmpdir}/fixture.pub"
openssl genpkey -algorithm ed25519 -out "${tmpdir}/fixture.key" 2>/dev/null
openssl pkey -in "${tmpdir}/fixture.key" -pubout -out "${AEGIS_MANIFEST_PUBKEY_PEM}" 2>/dev/null

# Prepare a fake manifest payload at a real file:// URL.
manifest_payload='{"git_sha":"deadbeef","channel":"stable"}'
real_path="${tmpdir}/real.manifest.json"
printf '%s\n' "${manifest_payload}" > "${real_path}"
openssl pkeyutl -sign -inkey "${tmpdir}/fixture.key" -rawin -in "${real_path}" -out "${real_path}.sig"
real_url="file://${real_path}"
REQUIRE_RELEASE_POLICY=0
ALLOW_HISTORICAL_POLICY=1
HISTORICAL_MANIFEST_SHA256="$(shasum -a 256 "${real_path}" | cut -d ' ' -f1)"
HISTORICAL_SIGNATURE_SHA256="$(shasum -a 256 "${real_path}.sig" | cut -d ' ' -f1)"
HOME="${tmpdir}/fixture-user"
AEGIS_HOST_ARCH=x86_64
missing_url="file://${tmpdir}/does-not-exist-primary.json"
missing_url_2="file://${tmpdir}/also-missing.json"

# Case 1: primary unreachable, single mirror serves it.
MANIFEST_URL_RESOLVED_BY_FALLBACK=""
dest="${tmpdir}/case1.manifest.json"
if ! download_url_with_fallback "${dest}" "${missing_url}" "${real_url}"; then
  fail "case 1: fallback should have succeeded via the second URL"
fi
[[ "${MANIFEST_URL_RESOLVED_BY_FALLBACK}" == "${real_url}" ]] \
  || fail "case 1: expected resolved URL to be the mirror; got '${MANIFEST_URL_RESOLVED_BY_FALLBACK}'"
[[ "$(cat "${dest}")" == "${manifest_payload}" ]] \
  || fail "case 1: downloaded manifest content does not match"

# Case 2: primary works → mirror not consulted, resolved == primary.
MANIFEST_URL_RESOLVED_BY_FALLBACK=""
dest="${tmpdir}/case2.manifest.json"
download_url_with_fallback "${dest}" "${real_url}" "${missing_url}"
[[ "${MANIFEST_URL_RESOLVED_BY_FALLBACK}" == "${real_url}" ]] \
  || fail "case 2: resolved URL should equal primary; got '${MANIFEST_URL_RESOLVED_BY_FALLBACK}'"

# Case 3: every URL fails → function returns 1.
MANIFEST_URL_RESOLVED_BY_FALLBACK=""
dest="${tmpdir}/case3.manifest.json"
if download_url_with_fallback "${dest}" "${missing_url}" "${missing_url_2}" 2>/dev/null; then
  fail "case 3: fallback should have failed with all URLs missing"
fi
[[ -z "${MANIFEST_URL_RESOLVED_BY_FALLBACK}" ]] \
  || fail "case 3: resolved URL should be empty on total failure; got '${MANIFEST_URL_RESOLVED_BY_FALLBACK}'"

# Case 4: list with empty entries is filtered (multi-mirror env list).
MANIFEST_URL_RESOLVED_BY_FALLBACK=""
dest="${tmpdir}/case4.manifest.json"
download_url_with_fallback "${dest}" "" "${missing_url}" "" "${real_url}" ""
[[ "${MANIFEST_URL_RESOLVED_BY_FALLBACK}" == "${real_url}" ]] \
  || fail "case 4: empty entries should be filtered; resolved='${MANIFEST_URL_RESOLVED_BY_FALLBACK}'"

echo "ok: bootstrap manifest fallback (4 cases: mirror, primary-only, total-failure, empty-filter)"
