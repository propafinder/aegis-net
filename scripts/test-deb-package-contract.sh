#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
export PATH="${HOME}/.cargo/bin:${PATH}"

python3 -I -B "${ROOT}/scripts/test-verify-deb-archive-ownership.py"

if ! command -v dpkg-deb >/dev/null 2>&1; then
  echo "dpkg-deb is required" >&2
  exit 1
fi

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/aegis-deb-contract.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT

# This package is built and inspected only on the current contract host.
# shellcheck source=scripts/lib/test-host-release-abi.sh
. "${ROOT}/scripts/lib/test-host-release-abi.sh"
aegis_test_use_host_release_abi "deb-package contract"
"${ROOT}/scripts/build-deb-package.sh" "${TMP_DIR}" >/dev/null

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

DEB_PATH="${TMP_DIR}/aegis_${VERSION}_${DEB_ARCH}.deb"
DEB_SHA256_PATH="${DEB_PATH}.sha256"
MANIFEST_PATH="${TMP_DIR}/deb-package.manifest.json"
EXTRACT_DIR="${TMP_DIR}/extract"
CTRL_DIR="${TMP_DIR}/control"

python3 -I -B "${ROOT}/scripts/verify-deb-archive-ownership.py" "${DEB_PATH}"

dpkg-deb -x "${DEB_PATH}" "${EXTRACT_DIR}"
dpkg-deb -e "${DEB_PATH}" "${CTRL_DIR}"

cargo run -q -p aegis-measure -- check-deb-package-contract-artifacts \
  --deb-path "${DEB_PATH}" \
  --deb-sha256-path "${DEB_SHA256_PATH}" \
  --manifest-path "${MANIFEST_PATH}" \
  --extract-dir "${EXTRACT_DIR}" \
  --control-dir "${CTRL_DIR}" \
  --version "${VERSION}" \
  --deb-arch "${DEB_ARCH}"

if command -v systemd-analyze >/dev/null 2>&1; then
  VERIFY_ROOT="${TMP_DIR}/verify-root"
  cp -R "${EXTRACT_DIR}/." "${VERIFY_ROOT}"
  mkdir -p "${VERIFY_ROOT}/usr/lib/systemd/system"
  cat > "${VERIFY_ROOT}/usr/lib/systemd/system/sysinit.target" <<'EOF'
[Unit]
Description=Stub sysinit target for deb verification
EOF
  cat > "${VERIFY_ROOT}/usr/lib/systemd/system/network.target" <<'EOF'
[Unit]
Description=Stub network target for deb verification
EOF
  cat > "${VERIFY_ROOT}/usr/lib/systemd/system/network-online.target" <<'EOF'
[Unit]
Description=Stub network-online target for deb verification
After=network.target
Wants=network.target
EOF
  cat > "${VERIFY_ROOT}/usr/lib/systemd/system/multi-user.target" <<'EOF'
[Unit]
Description=Stub multi-user target for deb verification
After=sysinit.target
EOF

  systemd-analyze verify --root="${VERIFY_ROOT}" \
    "${VERIFY_ROOT}/usr/lib/systemd/system/aegis-server.service" \
    "${VERIFY_ROOT}/usr/lib/systemd/system/aegis-client.service" >/dev/null
fi

echo "PASS: deb package contract"
