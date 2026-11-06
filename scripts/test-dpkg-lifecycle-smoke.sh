#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
export PATH="${HOME}/.cargo/bin:${PATH}"

if ! command -v dpkg >/dev/null 2>&1; then
  echo "dpkg is required" >&2
  exit 1
fi

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/aegis-dpkg-lifecycle.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT

# The lifecycle smoke installs into a temporary root on this host only.
# shellcheck source=scripts/lib/test-host-release-abi.sh
. "${ROOT}/scripts/lib/test-host-release-abi.sh"
aegis_test_use_host_release_abi "dpkg lifecycle smoke"
"${ROOT}/scripts/build-split-deb-packages.sh" "${TMP_DIR}" >/dev/null

# shellcheck source=scripts/lib/host-arch.sh
. "$(dirname "${BASH_SOURCE[0]}")/lib/host-arch.sh"
ARCH="$(host_arch)"
map_deb_arch() {
  case "$1" in
    x86_64) printf 'amd64\n' ;;
    aarch64|arm64) printf 'arm64\n' ;;
    armv7l) printf 'armhf\n' ;;
    *) printf '%s\n' "$1" ;;
  esac
}

DEB_ARCH="$(map_deb_arch "${ARCH}")"
VERSION="$(cargo run -q -p aegis-measure -- print-cargo-package-version --root "${ROOT}" --package-name aegis-server)"

SERVER_DEB="${TMP_DIR}/aegis-server_${VERSION}_${DEB_ARCH}.deb"
CLIENT_DEB="${TMP_DIR}/aegis-client_${VERSION}_${DEB_ARCH}.deb"
ROOTDIR="${TMP_DIR}/root"
ADMINDIR="${ROOTDIR}/var/lib/dpkg"
SHIMDIR="${TMP_DIR}/shims"
DPKG_LOG="${ROOTDIR}/var/log/dpkg.log"
HOOK_LOG="${TMP_DIR}/maintainer-hooks.log"

mkdir -p \
  "${ADMINDIR}/updates" \
  "${ADMINDIR}/info" \
  "${ADMINDIR}/triggers" \
  "${ROOTDIR}/var/log" \
  "${SHIMDIR}"
: > "${ADMINDIR}/status"
cat > "${SHIMDIR}/systemctl" <<EOF
#!/usr/bin/env bash
printf 'systemctl %s\n' "\$*" >> "${HOOK_LOG}"
exit 0
EOF
chmod 0755 "${SHIMDIR}/systemctl"
cat > "${SHIMDIR}/systemd-sysusers" <<EOF
#!/usr/bin/env bash
printf 'systemd-sysusers %s\n' "\$*" >> "${HOOK_LOG}"
exit 0
EOF
chmod 0755 "${SHIMDIR}/systemd-sysusers"
cat > "${SHIMDIR}/systemd-tmpfiles" <<EOF
#!/usr/bin/env bash
printf 'systemd-tmpfiles %s\n' "\$*" >> "${HOOK_LOG}"
exit 0
EOF
chmod 0755 "${SHIMDIR}/systemd-tmpfiles"

COMMON_DPKG_ARGS=(
  --root="${ROOTDIR}"
  --admindir="${ADMINDIR}"
  --log="${DPKG_LOG}"
  --force-not-root
  --force-bad-path
  --force-script-chrootless
  --force-depends
)

NEEDRESTART_SUSPEND=1 PATH="${SHIMDIR}:$PATH" \
  dpkg "${COMMON_DPKG_ARGS[@]}" --install "${SERVER_DEB}" "${CLIENT_DEB}" >/dev/null

cargo run -q -p aegis-measure -- check-dpkg-lifecycle-smoke-state \
  --phase installed \
  --rootdir "${ROOTDIR}" \
  --status-path "${ADMINDIR}/status" \
  --hook-log "${HOOK_LOG}"

NEEDRESTART_SUSPEND=1 PATH="${SHIMDIR}:$PATH" \
  dpkg "${COMMON_DPKG_ARGS[@]}" --remove aegis-client aegis-server >/dev/null

cargo run -q -p aegis-measure -- check-dpkg-lifecycle-smoke-state \
  --phase removed \
  --rootdir "${ROOTDIR}" \
  --status-path "${ADMINDIR}/status" \
  --hook-log "${HOOK_LOG}"

NEEDRESTART_SUSPEND=1 PATH="${SHIMDIR}:$PATH" \
  dpkg "${COMMON_DPKG_ARGS[@]}" --purge aegis-client aegis-server >/dev/null

cargo run -q -p aegis-measure -- check-dpkg-lifecycle-smoke-state \
  --phase purged \
  --rootdir "${ROOTDIR}" \
  --status-path "${ADMINDIR}/status" \
  --hook-log "${HOOK_LOG}"

echo "PASS: dpkg lifecycle smoke"
