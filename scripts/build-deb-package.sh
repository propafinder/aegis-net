#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
export PATH="${HOME}/.cargo/bin:${PATH}"

usage() {
  cat <<'EOF'
Usage:
  scripts/build-deb-package.sh <output-dir>

Builds a Debian package baseline on top of the canonical package-root layout:
  <output-dir>/aegis_<version>_<arch>.deb
  <output-dir>/aegis_<version>_<arch>.deb.sha256

This is the first package-manager deliverable over the existing release bundle
and package-root layers.
EOF
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

if [[ $# -ne 1 ]]; then
  usage >&2
  exit 1
fi

if ! command -v dpkg-deb >/dev/null 2>&1; then
  echo "dpkg-deb is required" >&2
  exit 1
fi

OUTPUT_DIR="$1"
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
META="$(cargo run --locked -q -p aegis-measure -- release-package-metadata --root "${ROOT}")"
VERSION="$(printf '%s\n' "${META}" | sed -n '2p')"

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/aegis-deb-build.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT

"${ROOT}/scripts/build-package-root.sh" "${TMP_DIR}" >/dev/null

PACKAGE_ROOT_DIR="${TMP_DIR}/aegis-package-root-${VERSION}-linux-${ARCH}"
ROOTFS_DIR="${PACKAGE_ROOT_DIR}/rootfs"
STAGE_DIR="${TMP_DIR}/deb-stage"
DEBIAN_DIR="${STAGE_DIR}/DEBIAN"
DEB_NAME="aegis_${VERSION}_${DEB_ARCH}.deb"
DEB_PATH="${OUTPUT_DIR}/${DEB_NAME}"
DEB_SHA256_PATH="${DEB_PATH}.sha256"

mkdir -p "${OUTPUT_DIR}"
UNVERIFIED_DIR="$(mktemp -d "${OUTPUT_DIR}/.aegis-deb-unverified.XXXXXX")"
trap 'rm -rf -- "${TMP_DIR}" "${UNVERIFIED_DIR}"' EXIT
mkdir -p "${DEBIAN_DIR}"

cp -R "${ROOTFS_DIR}/." "${STAGE_DIR}/"

cat > "${DEBIAN_DIR}/control" <<EOF
Package: aegis
Version: ${VERSION}
Section: net
Priority: optional
Architecture: ${DEB_ARCH}
Maintainer: AEGIS Packaging <packaging@aegis.invalid>
Depends: systemd, ca-certificates, bash, openssl, python3 (>= 3.11), iproute2, nftables, iptables, util-linux, coreutils
Description: AEGIS relay and Linux-first client runtime
 AEGIS packages both relay-server and client runtime roles together as a
 first Debian baseline. This package installs binaries, systemd units,
 env files, helper scripts and examples on top of the canonical package-root
 layout already used by the release bundle pipeline.
EOF

cat > "${DEBIAN_DIR}/postinst" <<'EOF'
#!/bin/sh
set -e

command -v systemd-sysusers >/dev/null 2>&1
command -v systemd-tmpfiles >/dev/null 2>&1
systemd-sysusers /usr/lib/sysusers.d/aegis-server.conf
systemd-tmpfiles --create /usr/lib/tmpfiles.d/aegis-server.conf
systemd-tmpfiles --create /usr/lib/tmpfiles.d/aegis-client.conf

# Only contact the booted system manager in the same root. A chroot with a
# bind-mounted /run must not reconfigure host units.
aegis_live_systemd() {
  [ -d /run/systemd/system ] || return 1
  [ -e /proc/1/root ] || return 1
  current_root=$(stat -Lc %d:%i /) || return 1
  init_root=$(stat -Lc %d:%i /proc/1/root) || return 1
  [ "$current_root" = "$init_root" ]
}

if aegis_live_systemd; then
  command -v systemctl >/dev/null 2>&1
  systemctl daemon-reload
  # A package upgrade must preserve an administrator's disabled state.
  if [ "${1:-}" = configure ] && [ -z "${2:-}" ]; then
    systemctl preset aegis-server.service
    systemctl preset aegis-client.service
  fi
fi

exit 0
EOF

cat > "${DEBIAN_DIR}/prerm" <<'EOF'
#!/bin/sh
set -e

case "${1:-}" in
  remove|deconfigure)
    if command -v systemctl >/dev/null 2>&1; then
      systemctl --no-reload disable --now aegis-server.service >/dev/null 2>&1 || true
      systemctl --no-reload disable --now aegis-client.service >/dev/null 2>&1 || true
    fi
    ;;
esac

exit 0
EOF

cat > "${DEBIAN_DIR}/postrm" <<'EOF'
#!/bin/sh
set -e

case "${1:-}" in
  purge)
    if command -v systemd-tmpfiles >/dev/null 2>&1; then
      systemd-tmpfiles --remove /usr/lib/tmpfiles.d/aegis-server.conf >/dev/null 2>&1 || true
      systemd-tmpfiles --remove /usr/lib/tmpfiles.d/aegis-client.conf >/dev/null 2>&1 || true
    fi
    ;;
esac

if command -v systemctl >/dev/null 2>&1; then
  systemctl daemon-reload >/dev/null 2>&1 || true
fi

exit 0
EOF

cat > "${DEBIAN_DIR}/conffiles" <<'EOF'
/etc/default/aegis-server
/etc/default/aegis-client
EOF

chmod 0755 "${DEBIAN_DIR}/postinst" "${DEBIAN_DIR}/prerm" "${DEBIAN_DIR}/postrm"

cargo run --locked -q -p aegis-measure -- write-deb-md5-sums \
  --stage-dir "${STAGE_DIR}" \
  --debian-dir "${DEBIAN_DIR}"

UNVERIFIED_DEB="${UNVERIFIED_DIR}/${DEB_NAME}"
dpkg-deb --root-owner-group --build -Zxz "${STAGE_DIR}" "${UNVERIFIED_DEB}" >/dev/null
python3 -I -B "${ROOT}/scripts/verify-deb-archive-ownership.py" "${UNVERIFIED_DEB}" >/dev/null

cargo run --locked -q -p aegis-measure -- write-archive-sha256 \
  --archive "${UNVERIFIED_DEB}" \
  --sha256-path "${UNVERIFIED_DIR}/${DEB_NAME}.sha256"

cargo run --locked -q -p aegis-measure -- build-deb-package-manifest \
  --output-dir "${UNVERIFIED_DIR}" \
  --deb-name "${DEB_NAME}" \
  --version "${VERSION}" \
  --deb-arch "${DEB_ARCH}" \
  --rootfs-dir "${ROOTFS_DIR}"

# The manifest is the completion marker. Previous output stays complete if
# build/ownership/sidecar/manifest validation fails before publication.
rm -f "${OUTPUT_DIR}/deb-package.manifest.json"
mv "${UNVERIFIED_DEB}" "${DEB_PATH}"
mv "${UNVERIFIED_DIR}/${DEB_NAME}.sha256" "${DEB_SHA256_PATH}"
mv "${UNVERIFIED_DIR}/deb-package.manifest.json" "${OUTPUT_DIR}/deb-package.manifest.json"

cat <<EOF
Debian package created
----------------------
Package:
  ${DEB_PATH}

Checksum:
  ${DEB_SHA256_PATH}

Manifest:
  ${OUTPUT_DIR}/deb-package.manifest.json
EOF
