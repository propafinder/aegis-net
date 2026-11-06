#!/usr/bin/env bash
set -euo pipefail
umask 022

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
export PATH="${HOME}/.cargo/bin:${PATH}"
# shellcheck source=scripts/lib/release-toolchain.sh
. "${ROOT}/scripts/lib/release-toolchain.sh"

usage() {
  cat <<'EOF'
Usage:
  scripts/build-package-root.sh <output-dir>

Builds release binaries and produces a package-root staging artifact:
  <output-dir>/aegis-package-root-<version>-linux-<arch>/
  <output-dir>/aegis-package-root-<version>-linux-<arch>.tar.gz

The package-root contains a canonical rootfs layout meant as a baseline for
future deb/rpm packaging work.
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

if ! command -v cargo >/dev/null 2>&1; then
  echo "cargo is required; install Rust via rustup first" >&2
  exit 1
fi

verify_release_toolchain

OUTPUT_DIR="$1"
# shellcheck source=scripts/lib/host-arch.sh
. "$(dirname "${BASH_SOURCE[0]}")/lib/host-arch.sh"
ARCH="$(host_arch)"
GIT_SHA="${AEGIS_BUILD_GIT_SHA:-$(git -C "${ROOT}" rev-parse HEAD 2>/dev/null || printf 'unknown')}"
BUILD_TIMESTAMP="${AEGIS_BUILD_TIMESTAMP:-$(release_source_timestamp)}"
export AEGIS_BUILD_GIT_SHA="${GIT_SHA}"
export AEGIS_BUILD_TIMESTAMP="${BUILD_TIMESTAMP}"
case "${ARCH}" in
  x86_64) TARGET_TRIPLE="x86_64-unknown-linux-gnu" ;;
  aarch64|arm64) TARGET_TRIPLE="aarch64-unknown-linux-gnu" ;;
  armv7l) TARGET_TRIPLE="armv7-unknown-linux-gnueabihf" ;;
  *) TARGET_TRIPLE="${ARCH}-unknown-linux-gnu" ;;
esac
if command -v sha256sum >/dev/null 2>&1; then
  CARGO_LOCK_SHA256="$(sha256sum "${ROOT}/Cargo.lock" | awk '{print $1}')"
else
  CARGO_LOCK_SHA256="$(shasum -a 256 "${ROOT}/Cargo.lock" | awk '{print $1}')"
fi
verify_package_lockfile() {
  local actual
  if command -v sha256sum >/dev/null 2>&1; then
    actual="$(sha256sum "${ROOT}/Cargo.lock" | awk '{print $1}')"
  else
    actual="$(shasum -a 256 "${ROOT}/Cargo.lock" | awk '{print $1}')"
  fi
  [[ "$actual" == "$CARGO_LOCK_SHA256" ]] || {
    echo 'Cargo.lock changed during package build; refusing package output.' >&2
    return 1
  }
}
export AEGIS_BUILD_TARGET="${TARGET_TRIPLE}"
export AEGIS_CARGO_LOCK_SHA256="${CARGO_LOCK_SHA256}"
HELPER_SCRIPTS=(
  "lib/root-state.sh"
  "lib/aegis_installer_auto_v2.py"
  "lib/aegis_auto_uninstall_journal.py"
  "lib/aegis_auto_capture.py"
  "lib/aegis_auto_capture_topology.py"
  "lib/aegis_auto_endpoint.py"
  "lib/aegis_auto_guard_policy.py"
  "lib/aegis_auto_foreign_policy.py"
  "lib/aegis_auto_foreign_monitor.py"
  "lib/aegis_auto_ufw_pins.json"
  "lib/aegis_initrd_policy.py"
  "lib/aegis_initrd_classic.py"
  "lib/aegis_auto_guardian.py"
  "lib/aegis_auto_guardian_watchdog.py"
  "lib/aegis_auto_terminal_witness.py"
  "lib/aegis_auto_terminal_boot_store.py"
  "lib/aegis_auto_terminal_register.py"
  "lib/aegis_auto_boot_transition.py"
  "lib/aegis_auto_launch.py"
  "lib/aegis_auto_native_witness.py"
  "lib/aegis_auto_sink.py"
  "lib/aegis_auto_trace_rollback.py"
  "lib/aegis_auto_witness_topology.py"
  "aegis-device-egress-guard.sh"
  "bootstrap-wide-linux-validation-host.sh"
  "generate-relay-materials.sh"
  "render-client-bundle.sh"
  "package-client-bundle.sh"
  "issue-fronted-bundle.sh"
  "aegis-origin-guard.sh"
  "aegis-wide-enable.sh"
  "aegis-wide-disable.sh"
  "purge-installed-aegis.sh"
  "aegis-ubuntu-uninstall.sh"
  "aegis-wide-persist-install.sh"
  "janitor-wide-linux-tproxy.sh"
  "setup-wide-linux-redirect.sh"
  "setup-wide-linux-tproxy.sh"
  "setup-wide-linux-nfqueue.sh"
  "validate-debian-package-host.sh"
  "verify-deb-archive-ownership.py"
  "verify-split-deb-package-set.py"
  "build-ubuntu-controlled-pilot-playbook.sh"
  "build-ubuntu-operator-reapply-canary.sh"
  "build-ubuntu-controlled-pilot-bundle.sh"
  "build-ubuntu-release-review.sh"
  "build-ubuntu-controlled-pilot-review-bundle.sh"
  "ubuntu-release-wave-status.sh"
  "build-ubuntu-release-wave-bundle.sh"
  "build-ubuntu-field-pilot-remote-bundle.sh"
  "build-post-release-stealth-wave-summary.sh"
  "mimicry-wire-validation-contract.sh"
  "build-mimicry-wire-witness-summary.sh"
  "validate-mimicry-wire-host.sh"
  "build-ubuntu-mimicry-next-contour.sh"
)
WIDE_HELPER_SCRIPTS=(
  "lib/root-state.sh"
  "lib/aegis_installer_auto_v2.py"
  "lib/aegis_auto_uninstall_journal.py"
  "lib/aegis_auto_capture.py"
  "lib/aegis_auto_capture_topology.py"
  "lib/aegis_auto_endpoint.py"
  "lib/aegis_auto_guard_policy.py"
  "lib/aegis_auto_foreign_policy.py"
  "lib/aegis_auto_foreign_monitor.py"
  "lib/aegis_auto_ufw_pins.json"
  "lib/aegis_initrd_policy.py"
  "lib/aegis_initrd_classic.py"
  "lib/aegis_auto_guardian.py"
  "lib/aegis_auto_guardian_watchdog.py"
  "lib/aegis_auto_terminal_witness.py"
  "lib/aegis_auto_terminal_boot_store.py"
  "lib/aegis_auto_terminal_register.py"
  "lib/aegis_auto_boot_transition.py"
  "lib/aegis_auto_launch.py"
  "lib/aegis_auto_native_witness.py"
  "lib/aegis_auto_sink.py"
  "lib/aegis_auto_trace_rollback.py"
  "lib/aegis_auto_witness_topology.py"
  "aegis-device-egress-guard.sh"
  "purge-installed-aegis.sh"
  "aegis-ubuntu-uninstall.sh"
  "aegis-wide-enable.sh"
  "aegis-wide-disable.sh"
  "aegis-wide-persist-install.sh"
  "janitor-wide-linux-tproxy.sh"
  "setup-wide-linux-redirect.sh"
  "setup-wide-linux-tproxy.sh"
  "setup-wide-linux-nfqueue.sh"
)
AUTO_SYSTEMD_UNITS=(
  "aegis-auto-config.service"
  "aegis-auto-capture-topology.service"
  "aegis-auto-guardian-watchdog.service"
  "aegis-auto-guardian.service"
  "aegis-auto-terminal-a@.service"
  "aegis-auto-terminal-b@.service"
  "aegis-auto-terminal-observer.service"
  "aegis-auto-terminal-transition.service"
  "aegis-auto-trace-rollback-actor.service"
  "aegis-auto-trace-rollback.service"
  "aegis-auto-trace-rollback.timer"
  "aegis-auto-witness-topology.service"
  "aegis-foreign-policy-monitor.service"
  "aegis-auto-clean-shutdown.service"
  "aegis-device-dhcp-refresh.service"
  "aegis-device-dhcp-refresh.timer"
)

META="$(cargo run --locked -q -p aegis-measure -- release-package-metadata --root "${ROOT}")"

TARGET_DIR="$(printf '%s\n' "${META}" | sed -n '1p')"
VERSION="$(printf '%s\n' "${META}" | sed -n '2p')"
verify_package_lockfile
PACKAGE_NAME="aegis-package-root-${VERSION}-linux-${ARCH}"
PACKAGE_DIR="${OUTPUT_DIR}/${PACKAGE_NAME}"
ROOTFS_DIR="${PACKAGE_DIR}/rootfs"
ARCHIVE_PATH="${OUTPUT_DIR}/${PACKAGE_NAME}.tar.gz"

render_template() {
  local template_path="$1"
  shift
  local rendered
  rendered="$(<"${template_path}")"
  while [[ $# -gt 1 ]]; do
    local needle="$1"
    local value="$2"
    shift 2
    rendered="${rendered//${needle}/${value}}"
  done
  printf '%s\n' "${rendered}"
}

mkdir -p "${OUTPUT_DIR}"
rm -rf "${PACKAGE_DIR}" "${ARCHIVE_PATH}"

cd "${ROOT}"
# aws-lc-sys (the chrome-like-tls backend) needs cmake. Check before the long
# server build so a runner without it fails in a second with a clear message
# instead of ten minutes in with a native-build error.
if ! command -v cmake >/dev/null 2>&1; then
  echo "cmake is required to build the chrome-like-tls feature (aws-lc-sys)." >&2
  echo "A build without it cannot produce a Chrome-class TLS ClientHello." >&2
  exit 1
fi
AEGIS_BUILD_FEATURES="none" cargo build --locked --release -p aegis-server
AEGIS_BUILD_FEATURES="raw-socket,chrome-like-tls,chrome-like-quic" \
  cargo build --locked --release -p aegis-client --features raw-socket,chrome-like-tls,chrome-like-quic \
    --target "${TARGET_TRIPLE}"

verify_package_lockfile

# Native packages are generic Linux release artifacts too. Enforce the same
# glibc baseline as the tar bundle even when this script is invoked directly.
# shellcheck source=scripts/lib/release-abi.sh
. "${ROOT}/scripts/lib/release-abi.sh"
verify_linux_release_abi \
  "${TARGET_DIR}/release/aegis-server" \
  "${TARGET_DIR}/${TARGET_TRIPLE}/release/aegis-client"

mkdir -p \
  "${ROOTFS_DIR}/usr/local/bin" \
  "${ROOTFS_DIR}/usr/lib/systemd/system" \
  "${ROOTFS_DIR}/usr/lib/systemd/system-preset" \
  "${ROOTFS_DIR}/usr/lib/sysusers.d" \
  "${ROOTFS_DIR}/usr/lib/tmpfiles.d" \
  "${ROOTFS_DIR}/etc/default" \
  "${ROOTFS_DIR}/etc/systemd/system" \
  "${ROOTFS_DIR}/etc/aegis/server" \
  "${ROOTFS_DIR}/etc/aegis/client" \
  "${ROOTFS_DIR}/var/lib/aegis-server" \
  "${ROOTFS_DIR}/var/lib/aegis-client" \
  "${ROOTFS_DIR}/var/log/aegis-client" \
  "${ROOTFS_DIR}/usr/local/lib/aegis/helpers" \
  "${ROOTFS_DIR}/usr/local/sbin" \
  "${ROOTFS_DIR}/usr/share/aegis/examples" \
  "${ROOTFS_DIR}/usr/share/aegis/scripts" \
  "${ROOTFS_DIR}/usr/share/doc/aegis"

cp "${TARGET_DIR}/release/aegis-server" "${ROOTFS_DIR}/usr/local/bin/aegis-server"
cp "${TARGET_DIR}/${TARGET_TRIPLE}/release/aegis-client" "${ROOTFS_DIR}/usr/local/bin/aegis-client"
cp "${ROOT}/aegis-server.toml.example" "${ROOTFS_DIR}/usr/share/aegis/examples/aegis-server.toml.example"
cp "${ROOT}/config.example.toml" "${ROOTFS_DIR}/usr/share/aegis/examples/config.example.toml"
cp "${ROOT}/packaging/env/aegis-server.env.example" "${ROOTFS_DIR}/etc/default/aegis-server"
cp "${ROOT}/packaging/env/aegis-client.env.example" "${ROOTFS_DIR}/etc/default/aegis-client"
cp "${ROOT}/packaging/systemd-preset/90-aegis.preset" "${ROOTFS_DIR}/usr/lib/systemd/system-preset/90-aegis.preset"
cp "${ROOT}/packaging/systemd-preset/90-aegis-server.preset" "${ROOTFS_DIR}/usr/lib/systemd/system-preset/90-aegis-server.preset"
cp "${ROOT}/packaging/systemd-preset/90-aegis-client.preset" "${ROOTFS_DIR}/usr/lib/systemd/system-preset/90-aegis-client.preset"
cp "${ROOT}/packaging/sysusers/aegis-server.conf" "${ROOTFS_DIR}/usr/lib/sysusers.d/aegis-server.conf"
cp "${ROOT}/packaging/tmpfiles/aegis-server.conf" "${ROOTFS_DIR}/usr/lib/tmpfiles.d/aegis-server.conf"
cp "${ROOT}/packaging/tmpfiles/aegis-client.conf" "${ROOTFS_DIR}/usr/lib/tmpfiles.d/aegis-client.conf"
cp "${ROOT}/scripts/aegis-origin-guard.sh" "${ROOTFS_DIR}/usr/local/sbin/aegis-origin-guard.sh"
cp "${ROOT}/packaging/systemd/aegis-origin-guard.service" "${ROOTFS_DIR}/usr/lib/systemd/system/aegis-origin-guard.service"
for unit in "${AUTO_SYSTEMD_UNITS[@]}"; do
  cp "${ROOT}/packaging/systemd/${unit}" "${ROOTFS_DIR}/etc/systemd/system/${unit}"
  chmod 0644 "${ROOTFS_DIR}/etc/systemd/system/${unit}"
done
for helper_script in "${HELPER_SCRIPTS[@]}"; do
  mkdir -p "$(dirname "${ROOTFS_DIR}/usr/share/aegis/scripts/${helper_script}")"
  cp "${ROOT}/scripts/${helper_script}" "${ROOTFS_DIR}/usr/share/aegis/scripts/${helper_script}"
done
for helper_script in "${WIDE_HELPER_SCRIPTS[@]}"; do
  mkdir -p "$(dirname "${ROOTFS_DIR}/usr/local/lib/aegis/helpers/${helper_script}")"
  cp "${ROOT}/scripts/${helper_script}" "${ROOTFS_DIR}/usr/local/lib/aegis/helpers/${helper_script}"
done
mkdir -p "${ROOTFS_DIR}/usr/local/lib/aegis/helpers/lib" \
  "${ROOTFS_DIR}/usr/share/aegis/scripts/lib"
cp "${ROOT}/packaging/systemd/system-shutdown/aegis-auto-terminal-hook" \
  "${ROOTFS_DIR}/usr/local/lib/aegis/helpers/lib/aegis-auto-terminal-hook"
cp "${ROOT}/packaging/systemd/system-shutdown/aegis-auto-terminal-hook" \
  "${ROOTFS_DIR}/usr/share/aegis/scripts/lib/aegis-auto-terminal-hook"
cp "${ROOT}/README.md" "${ROOTFS_DIR}/usr/share/doc/aegis/README.md"
for project_license in LICENSE-MIT LICENSE-APACHE NOTICE THIRD-PARTY-NOTICES; do
  cp "${ROOT}/${project_license}" "${ROOTFS_DIR}/usr/share/doc/aegis/${project_license}"
  chmod 0644 "${ROOTFS_DIR}/usr/share/doc/aegis/${project_license}"
done
mkdir -p "${ROOTFS_DIR}/usr/share/doc/aegis/third-party/h2"
cp "${ROOT}/third_party/h2/LICENSE" "${ROOTFS_DIR}/usr/share/doc/aegis/third-party/h2/LICENSE"
chmod 0644 "${ROOTFS_DIR}/usr/share/doc/aegis/third-party/h2/LICENSE"
mkdir -p "${ROOTFS_DIR}/usr/share/doc/aegis/third-party/tungstenite"
for license_file in LICENSE-MIT LICENSE-APACHE; do
  cp "${ROOT}/third_party/tungstenite/${license_file}" "${ROOTFS_DIR}/usr/share/doc/aegis/third-party/tungstenite/${license_file}"
  chmod 0644 "${ROOTFS_DIR}/usr/share/doc/aegis/third-party/tungstenite/${license_file}"
done
cp "${ROOT}/packaging/debian/README.Debian" "${ROOTFS_DIR}/usr/share/doc/aegis/README.Debian"
cp "${ROOT}/packaging/debian/README.server.Debian" "${ROOTFS_DIR}/usr/share/doc/aegis/README.server.Debian"
cp "${ROOT}/packaging/debian/README.client.Debian" "${ROOTFS_DIR}/usr/share/doc/aegis/README.client.Debian"

render_template "${ROOT}/packaging/systemd/aegis-server.service" \
  "__AEGIS_SERVER_ENV_FILE__" "/etc/default/aegis-server" \
  "__AEGIS_SERVER_STATE_DIR__" "/var/lib/aegis-server" \
  "__AEGIS_SERVER_BIN__" "/usr/local/bin/aegis-server" \
  "__AEGIS_SERVER_CONFIG__" "/etc/aegis/server/aegis-server.toml" \
  "__AEGIS_SERVER_USER__" "aegis" \
  "__AEGIS_SERVER_GROUP__" "aegis" \
  > "${ROOTFS_DIR}/usr/lib/systemd/system/aegis-server.service"

render_template "${ROOT}/packaging/systemd/aegis-client.service" \
  "__AEGIS_CLIENT_ENV_FILE__" "/etc/default/aegis-client" \
  "__AEGIS_CLIENT_STATE_DIR__" "/var/lib/aegis-client" \
  "__AEGIS_CLIENT_BIN__" "/usr/local/bin/aegis-client" \
  "__AEGIS_CLIENT_CONFIG__" "/etc/aegis/client/aegis.toml" \
  "__AEGIS_CLIENT_RUNTIME_EVENTS_JSONL__" "/var/log/aegis-client/runtime-events.jsonl" \
  > "${ROOTFS_DIR}/usr/lib/systemd/system/aegis-client.service"

chmod 0755 \
  "${ROOTFS_DIR}/usr/local/bin/aegis-server" \
  "${ROOTFS_DIR}/usr/local/bin/aegis-client" \
  "${ROOTFS_DIR}/usr/local/sbin/aegis-origin-guard.sh"
for helper_script in "${HELPER_SCRIPTS[@]}"; do
  chmod 0755 "${ROOTFS_DIR}/usr/share/aegis/scripts/${helper_script}"
done
for helper_script in "${WIDE_HELPER_SCRIPTS[@]}"; do
  case "${helper_script}" in
    lib/aegis_auto_*|lib/aegis_installer_auto_v2.py|lib/aegis_initrd_policy.py|lib/aegis_initrd_classic.py) chmod 0500 "${ROOTFS_DIR}/usr/local/lib/aegis/helpers/${helper_script}" ;;
    *) chmod 0755 "${ROOTFS_DIR}/usr/local/lib/aegis/helpers/${helper_script}" ;;
  esac
done
chmod 0500 "${ROOTFS_DIR}/usr/local/lib/aegis/helpers/lib/aegis-auto-terminal-hook"
chmod 0755 "${ROOTFS_DIR}/usr/share/aegis/scripts/lib/aegis-auto-terminal-hook"

cargo run --locked -q -p aegis-measure -- build-package-root-manifest \
  --package-dir "${PACKAGE_DIR}" \
  --rootfs-dir "${ROOTFS_DIR}" \
  --version "${VERSION}" \
  --arch "${ARCH}" \
  --target-triple "${TARGET_TRIPLE}" \
  --git-sha "${GIT_SHA}" \
  --build-timestamp "${BUILD_TIMESTAMP}"

verify_package_lockfile

tar --owner=0 --group=0 --numeric-owner -C "${OUTPUT_DIR}" -czf "${ARCHIVE_PATH}" "${PACKAGE_NAME}"

cat <<EOF
Package-root artifact created
----------------------------
Package directory:
  ${PACKAGE_DIR}

Rootfs:
  ${ROOTFS_DIR}

Archive:
  ${ARCHIVE_PATH}

This staging layout is intended as the next baseline for deb/rpm packaging work.
EOF
