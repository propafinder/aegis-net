#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
export PATH="${HOME}/.cargo/bin:${PATH}"

if ! command -v rpmbuild >/dev/null 2>&1 \
  || ! command -v rpm >/dev/null 2>&1 \
  || ! command -v rpm2cpio >/dev/null 2>&1 \
  || ! command -v cpio >/dev/null 2>&1; then
  echo "SKIP: rpmbuild/rpm/rpm2cpio/cpio are unavailable"
  exit 0
fi

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/aegis-rpm-contract.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT

# These packages are built and inspected only on the current contract host.
# shellcheck source=scripts/lib/test-host-release-abi.sh
. "${ROOT}/scripts/lib/test-host-release-abi.sh"
aegis_test_use_host_release_abi "rpm-packages contract"
"${ROOT}/scripts/build-rpm-packages.sh" "${TMP_DIR}" >/dev/null

# shellcheck source=scripts/lib/host-arch.sh
. "$(dirname "${BASH_SOURCE[0]}")/lib/host-arch.sh"
ARCH="$(host_arch)"
VERSION="$(
  sed -n 's/^version = "\(.*\)"/\1/p' "${ROOT}/aegis-server/Cargo.toml" | head -n 1
)"

SERVER_RPM="$(printf '%s\n' "${TMP_DIR}"/aegis-server-"${VERSION}"-1*.${ARCH}.rpm)"
CLIENT_RPM="$(printf '%s\n' "${TMP_DIR}"/aegis-client-"${VERSION}"-1*.${ARCH}.rpm)"
MANIFEST_PATH="${TMP_DIR}/rpm-packages.manifest.json"

for path in "${SERVER_RPM}" "${CLIENT_RPM}" "${MANIFEST_PATH}"; do
  if [[ ! -f "${path}" ]]; then
    echo "missing rpm contract artifact: ${path}" >&2
    exit 1
  fi
done

jq -e '
  (.packages | type == "object")
  and (.packages["aegis-server"] != null)
  and (.packages["aegis-client"] != null)
' "${MANIFEST_PATH}" >/dev/null

SERVER_FILES="$(rpm -qpl "${SERVER_RPM}")"
CLIENT_FILES="$(rpm -qpl "${CLIENT_RPM}")"
SERVER_SCRIPTS="$(rpm -qp --scripts "${SERVER_RPM}")"
CLIENT_SCRIPTS="$(rpm -qp --scripts "${CLIENT_RPM}")"

RPM_PAYLOAD="${TMP_DIR}/payload"
mkdir -p "${RPM_PAYLOAD}"
(
  cd "${RPM_PAYLOAD}"
  rpm2cpio "${SERVER_RPM}" | cpio -idmu --quiet
  rpm2cpio "${CLIENT_RPM}" | cpio -idmu --quiet
)
python3 -I -B - "${RPM_PAYLOAD}/usr/lib/tmpfiles.d/aegis-client.conf" <<'PY_TMPFILES'
import pathlib, sys
rows = [line.split() for line in pathlib.Path(sys.argv[1]).read_text().splitlines()]
for path in ('/var/lib/aegis-client', '/etc/aegis/client'):
    assert [row for row in rows if row[1] == path] == [['d', path, '-', '-', '-', '-']]
assert ['d', '/var/log/aegis-client', '0755', 'root', 'root', '-'] in rows
PY_TMPFILES
for binary_name in aegis-server aegis-client; do
  "${RPM_PAYLOAD}/usr/local/bin/${binary_name}" --version | grep -Eq 'cargo-lock [0-9a-f]{64}'
done

require_contains() {
  local haystack="$1"
  local needle="$2"
  if [[ "${haystack}" != *"${needle}"* ]]; then
    echo "missing expected rpm content: ${needle}" >&2
    exit 1
  fi
}

reject_contains() {
  local haystack="$1"
  local needle="$2"
  if [[ "${haystack}" == *"${needle}"* ]]; then
    echo "unexpected rpm content: ${needle}" >&2
    exit 1
  fi
}

require_contains "${SERVER_FILES}" "/usr/local/bin/aegis-server"
require_contains "${SERVER_FILES}" "/usr/lib/systemd/system/aegis-server.service"
require_contains "${SERVER_FILES}" "/usr/lib/systemd/system-preset/90-aegis-server.preset"
require_contains "${SERVER_FILES}" "/usr/share/aegis/scripts/package-client-bundle.sh"
require_contains "${SERVER_FILES}" "/usr/share/doc/aegis/README.server.Debian"
reject_contains "${SERVER_FILES}" "/usr/local/bin/aegis-client"

require_contains "${CLIENT_FILES}" "/usr/local/bin/aegis-client"
require_contains "${CLIENT_FILES}" "/usr/lib/systemd/system/aegis-client.service"
require_contains "${CLIENT_FILES}" "/usr/lib/systemd/system-preset/90-aegis-client.preset"
require_contains "${CLIENT_FILES}" "/usr/share/doc/aegis/README.client.Debian"
reject_contains "${CLIENT_FILES}" "/usr/local/bin/aegis-server"

require_contains "${SERVER_SCRIPTS}" "systemctl preset aegis-server.service"
require_contains "${SERVER_SCRIPTS}" "systemctl --no-reload disable --now aegis-server.service"
require_contains "${SERVER_SCRIPTS}" "systemd-tmpfiles --remove /usr/lib/tmpfiles.d/aegis-server.conf"
require_contains "${CLIENT_SCRIPTS}" "systemctl preset aegis-client.service"
require_contains "${CLIENT_SCRIPTS}" "systemctl --no-reload disable --now aegis-client.service"
require_contains "${CLIENT_SCRIPTS}" "systemd-tmpfiles --remove /usr/lib/tmpfiles.d/aegis-client.conf"

echo "PASS: rpm packages contract"
