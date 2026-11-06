#!/usr/bin/env bash
# Contract: a generated RPM spec must never list the same path twice in %files.
#
# rpmbuild rejects such a spec outright ("File listed twice"), which is how the
# release-delivery step broke: the config file was emitted as
# %config(noreplace) *and* included in the package's file list.
#
# The existing rpm contract test cannot catch this — it skips wherever rpmbuild
# is unavailable, which is most developer machines. This one only needs bash,
# so the failure is caught before it reaches CI.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BUILDER="${ROOT}/scripts/build-rpm-packages.sh"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/aegis-rpm-spec-contract.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT

# Pull just the spec writer out of the builder; sourcing the whole script would
# run a real package build.
sed -n '/^write_spec() {/,/^}/p' "${BUILDER}" > "${TMP_DIR}/write_spec.sh"
if ! grep -q '^write_spec() {' "${TMP_DIR}/write_spec.sh"; then
  echo "FAIL: could not extract write_spec from ${BUILDER}" >&2
  exit 1
fi

VERSION="0.0.0"
ARCH="x86_64"
# shellcheck disable=SC1091
. "${TMP_DIR}/write_spec.sh"

assert_no_duplicates() {
  local label="$1" spec="$2"
  local files dupes
  files="$(sed -n '/^%files/,$p' "${spec}" | sed '/^%files$/d;/^%defattr/d;/^$/d' \
    | sed 's/^%config(noreplace) //;s/^%dir //')"
  dupes="$(printf '%s\n' "${files}" | sort | uniq -d)"
  if [[ -n "${dupes}" ]]; then
    echo "FAIL: ${label} lists these paths more than once in %files:" >&2
    printf '  %s\n' ${dupes} >&2
    exit 1
  fi
  echo "PASS: ${label} lists every path exactly once"
}

# The real inputs, mirroring the builder's call sites. A path present in both
# the config slot and the file list is exactly the shape that broke the build.
SERVER_DIRS=$'%dir /etc/aegis/server\n%dir /var/lib/aegis-server'
SERVER_FILES=$'/usr/local/bin/aegis-server\n/usr/lib/systemd/system/aegis-server.service\n/etc/default/aegis-server\n/usr/share/doc/aegis/README.md'
CLIENT_DIRS=$'%dir /etc/aegis/client\n%dir /var/lib/aegis-client\n%dir /var/log/aegis-client'
CLIENT_FILES=$'/usr/local/bin/aegis-client\n/usr/lib/systemd/system/aegis-client.service\n/etc/default/aegis-client\n/usr/share/doc/aegis/README.client.Debian'

write_spec "${TMP_DIR}/server.spec" "aegis-server" "AEGIS relay server" \
  "src.tar.gz" "srcroot" "/etc/default/aegis-server" \
  "${SERVER_DIRS}" "${SERVER_FILES}" "post" "preun" "postun"
assert_no_duplicates "aegis-server" "${TMP_DIR}/server.spec"

write_spec "${TMP_DIR}/client.spec" "aegis-client" "AEGIS client" \
  "src.tar.gz" "srcroot" "/etc/default/aegis-client" \
  "${CLIENT_DIRS}" "${CLIENT_FILES}" "post" "preun" "postun"
assert_no_duplicates "aegis-client" "${TMP_DIR}/client.spec"

# The config must still be there — marked %config(noreplace), so an upgrade
# does not overwrite an operator's edits.
for pkg in server client; do
  if ! grep -q "^%config(noreplace) /etc/default/aegis-${pkg}$" "${TMP_DIR}/${pkg}.spec"; then
    echo "FAIL: aegis-${pkg} lost its %config(noreplace) entry" >&2
    exit 1
  fi
done
echo "PASS: both configs remain %config(noreplace)"

# And nothing else was filtered out along with it.
for path in /usr/local/bin/aegis-client /usr/share/doc/aegis/README.client.Debian; do
  if ! grep -qF "${path}" "${TMP_DIR}/client.spec"; then
    echo "FAIL: ${path} went missing from the client spec" >&2
    exit 1
  fi
done
echo "PASS: non-config files are untouched"
