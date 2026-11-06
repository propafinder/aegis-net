#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
export PATH="${HOME}/.cargo/bin:${PATH}"

if ! command -v cargo >/dev/null 2>&1; then
  echo "cargo is required; install Rust via rustup first" >&2
  exit 1
fi

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/aegis-package-root.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT

# This package root is a current-host contract fixture, not a portable release.
# shellcheck source=scripts/lib/test-host-release-abi.sh
. "${ROOT}/scripts/lib/test-host-release-abi.sh"
aegis_test_use_host_release_abi "package-root contract"
"${ROOT}/scripts/build-package-root.sh" "${TMP_DIR}" >/dev/null

# shellcheck source=scripts/lib/host-arch.sh
. "$(dirname "${BASH_SOURCE[0]}")/lib/host-arch.sh"
ARCH="$(host_arch)"
VERSION="$(
  sed -n 's/^version = "\(.*\)"/\1/p' "${ROOT}/aegis-server/Cargo.toml" | head -n 1
)"

PACKAGE_DIR="${TMP_DIR}/aegis-package-root-${VERSION}-linux-${ARCH}"
ROOTFS_DIR="${PACKAGE_DIR}/rootfs"
ARCHIVE_PATH="${PACKAGE_DIR}.tar.gz"

MANIFEST_JSON="${PACKAGE_DIR}/package-root.manifest.json"
SHA256SUMS="${PACKAGE_DIR}/SHA256SUMS"
SERVER_UNIT="${ROOTFS_DIR}/usr/lib/systemd/system/aegis-server.service"
CLIENT_UNIT="${ROOTFS_DIR}/usr/lib/systemd/system/aegis-client.service"

if [[ ! -d "${PACKAGE_DIR}" || ! -d "${ROOTFS_DIR}" || ! -f "${ARCHIVE_PATH}" ]]; then
  echo "missing package-root output" >&2
  exit 1
fi

jq -e '
  .schema == "aegis_package_root_manifest_v2"
  and .rootfs_dir == "rootfs"
  and (.cargo_lock_sha256 | test("^[0-9a-f]{64}$"))
  and .runtime_abi.libc_family == "glibc"
  and (.runtime_abi.generic_linux_min_glibc != "unknown")
  and (.runtime_abi.binary_required_glibc["aegis-server"] != "unknown")
  and (.runtime_abi.binary_required_glibc["aegis-client"] != "unknown")
  and (.binaries["aegis-server"].sha256 | test("^[0-9a-f]{64}$"))
  and (.binaries["aegis-client"].sha256 | test("^[0-9a-f]{64}$"))
  and .runtime_paths.server_binary == "/usr/local/bin/aegis-server"
  and .runtime_paths.client_binary == "/usr/local/bin/aegis-client"
  and .runtime_paths.client_wide_helper_dir == "/usr/local/lib/aegis/helpers"
  and .runtime_paths.preset_policy == "/usr/lib/systemd/system-preset/90-aegis.preset"
  and .runtime_paths.server_preset_policy == "/usr/lib/systemd/system-preset/90-aegis-server.preset"
  and .runtime_paths.client_preset_policy == "/usr/lib/systemd/system-preset/90-aegis-client.preset"
  and .runtime_paths.server_sysusers == "/usr/lib/sysusers.d/aegis-server.conf"
  and .runtime_paths.server_tmpfiles == "/usr/lib/tmpfiles.d/aegis-server.conf"
  and .runtime_paths.client_tmpfiles == "/usr/lib/tmpfiles.d/aegis-client.conf"
  and (.files | index("usr/lib/systemd/system/aegis-server.service") != null)
  and (.files | index("usr/lib/systemd/system/aegis-client.service") != null)
  and (.files | index("usr/lib/systemd/system/aegis-origin-guard.service") != null)
  and (.files | index("usr/lib/systemd/system-preset/90-aegis.preset") != null)
  and (.files | index("usr/lib/systemd/system-preset/90-aegis-server.preset") != null)
  and (.files | index("usr/lib/systemd/system-preset/90-aegis-client.preset") != null)
  and (.files | index("usr/lib/sysusers.d/aegis-server.conf") != null)
  and (.files | index("usr/lib/tmpfiles.d/aegis-server.conf") != null)
  and (.files | index("usr/lib/tmpfiles.d/aegis-client.conf") != null)
  and (.files | index("usr/share/aegis/examples/aegis-server.toml.example") != null)
  and (.files | index("usr/share/aegis/examples/config.example.toml") != null)
  and (.files | index("usr/share/aegis/scripts/bootstrap-wide-linux-validation-host.sh") != null)
  and (.files | index("usr/share/aegis/scripts/lib/root-state.sh") != null)
  and (.files | index("usr/local/lib/aegis/helpers/lib/root-state.sh") != null)
  and (.files | index("usr/share/aegis/scripts/package-client-bundle.sh") != null)
  and (.files | index("usr/share/aegis/scripts/issue-fronted-bundle.sh") != null)
  and (.files | index("usr/share/aegis/scripts/aegis-origin-guard.sh") != null)
  and (.files | index("usr/local/sbin/aegis-origin-guard.sh") != null)
  and (.files | index("usr/share/aegis/scripts/aegis-wide-enable.sh") != null)
  and (.files | index("usr/share/aegis/scripts/aegis-wide-disable.sh") != null)
  and (.files | index("usr/share/aegis/scripts/aegis-wide-persist-install.sh") != null)
  and (.files | index("usr/share/aegis/scripts/janitor-wide-linux-tproxy.sh") != null)
  and (.files | index("usr/share/aegis/scripts/setup-wide-linux-redirect.sh") != null)
  and (.files | index("usr/share/aegis/scripts/validate-debian-package-host.sh") != null)
  and (.files | index("usr/share/aegis/scripts/build-ubuntu-field-pilot-remote-bundle.sh") != null)
  and (.files | index("usr/share/aegis/scripts/build-post-release-stealth-wave-summary.sh") != null)
  and (.files | index("usr/share/aegis/scripts/build-ubuntu-mimicry-next-contour.sh") != null)
  and (.files | index("usr/share/aegis/scripts/setup-wide-linux-tproxy.sh") != null)
  and (.files | index("usr/local/lib/aegis/helpers/aegis-wide-enable.sh") != null)
  and (.files | index("usr/local/lib/aegis/helpers/aegis-wide-disable.sh") != null)
  and (.files | index("usr/local/lib/aegis/helpers/purge-installed-aegis.sh") != null)
  and (.files | index("usr/local/lib/aegis/helpers/aegis-ubuntu-uninstall.sh") != null)
  and (.files | index("usr/local/lib/aegis/helpers/aegis-wide-persist-install.sh") != null)
  and (.files | index("usr/local/lib/aegis/helpers/janitor-wide-linux-tproxy.sh") != null)
  and (.files | index("usr/local/lib/aegis/helpers/setup-wide-linux-redirect.sh") != null)
  and (.files | index("usr/local/lib/aegis/helpers/setup-wide-linux-tproxy.sh") != null)
' "${MANIFEST_JSON}" >/dev/null

grep -Eq ' usr/local/bin/aegis-server$' "${SHA256SUMS}"
grep -Eq ' usr/local/bin/aegis-client$' "${SHA256SUMS}"

if grep -Fq -- "__AEGIS_" "${SERVER_UNIT}"; then
  echo "server package unit still has placeholders" >&2
  exit 1
fi
if grep -Fq -- "__AEGIS_" "${CLIENT_UNIT}"; then
  echo "client package unit still has placeholders" >&2
  exit 1
fi
grep -Fq -- "/usr/local/bin/aegis-server --config /etc/aegis/server/aegis-server.toml" "${SERVER_UNIT}"
grep -Fq -- "/usr/local/bin/aegis-client --config /etc/aegis/client/aegis.toml --runtime-events-jsonl /var/log/aegis-client/runtime-events.jsonl" "${CLIENT_UNIT}"

for path in \
  "${ROOTFS_DIR}/usr/lib/sysusers.d/aegis-server.conf" \
  "${ROOTFS_DIR}/usr/lib/systemd/system-preset/90-aegis.preset" \
  "${ROOTFS_DIR}/usr/lib/systemd/system-preset/90-aegis-server.preset" \
  "${ROOTFS_DIR}/usr/lib/systemd/system-preset/90-aegis-client.preset" \
  "${ROOTFS_DIR}/usr/lib/tmpfiles.d/aegis-server.conf" \
  "${ROOTFS_DIR}/usr/lib/tmpfiles.d/aegis-client.conf" \
  "${ROOTFS_DIR}/usr/share/aegis/scripts/bootstrap-wide-linux-validation-host.sh" \
  "${ROOTFS_DIR}/usr/share/aegis/scripts/package-client-bundle.sh" \
  "${ROOTFS_DIR}/usr/share/aegis/scripts/issue-fronted-bundle.sh" \
  "${ROOTFS_DIR}/usr/share/aegis/scripts/aegis-origin-guard.sh" \
  "${ROOTFS_DIR}/usr/local/sbin/aegis-origin-guard.sh" \
  "${ROOTFS_DIR}/usr/lib/systemd/system/aegis-origin-guard.service" \
  "${ROOTFS_DIR}/usr/share/aegis/scripts/aegis-wide-enable.sh" \
  "${ROOTFS_DIR}/usr/share/aegis/scripts/aegis-wide-disable.sh" \
  "${ROOTFS_DIR}/usr/share/aegis/scripts/aegis-wide-persist-install.sh" \
  "${ROOTFS_DIR}/usr/share/aegis/scripts/janitor-wide-linux-tproxy.sh" \
  "${ROOTFS_DIR}/usr/share/aegis/scripts/setup-wide-linux-redirect.sh" \
  "${ROOTFS_DIR}/usr/share/aegis/scripts/validate-debian-package-host.sh" \
  "${ROOTFS_DIR}/usr/share/aegis/scripts/build-ubuntu-field-pilot-remote-bundle.sh" \
  "${ROOTFS_DIR}/usr/share/aegis/scripts/build-post-release-stealth-wave-summary.sh" \
  "${ROOTFS_DIR}/usr/share/aegis/scripts/build-ubuntu-mimicry-next-contour.sh" \
  "${ROOTFS_DIR}/usr/share/aegis/scripts/setup-wide-linux-tproxy.sh" \
  "${ROOTFS_DIR}/usr/local/lib/aegis/helpers/aegis-wide-enable.sh" \
  "${ROOTFS_DIR}/usr/local/lib/aegis/helpers/aegis-wide-disable.sh" \
  "${ROOTFS_DIR}/usr/local/lib/aegis/helpers/purge-installed-aegis.sh" \
  "${ROOTFS_DIR}/usr/local/lib/aegis/helpers/aegis-ubuntu-uninstall.sh" \
  "${ROOTFS_DIR}/usr/local/lib/aegis/helpers/aegis-wide-persist-install.sh" \
  "${ROOTFS_DIR}/usr/local/lib/aegis/helpers/janitor-wide-linux-tproxy.sh" \
  "${ROOTFS_DIR}/usr/local/lib/aegis/helpers/setup-wide-linux-redirect.sh" \
  "${ROOTFS_DIR}/usr/local/lib/aegis/helpers/setup-wide-linux-tproxy.sh" \
  "${ROOTFS_DIR}/usr/share/doc/aegis/README.Debian" \
  "${ROOTFS_DIR}/usr/share/doc/aegis/README.server.Debian" \
  "${ROOTFS_DIR}/usr/share/doc/aegis/README.client.Debian"; do
  if [[ ! -f "${path}" ]]; then
    echo "missing package-root file: ${path}" >&2
    exit 1
  fi
done

if command -v systemd-analyze >/dev/null 2>&1; then
  VERIFY_ROOT="${TMP_DIR}/verify-root"
  cp -R "${ROOTFS_DIR}" "${VERIFY_ROOT}"
  mkdir -p "${VERIFY_ROOT}/usr/lib/systemd/system"
  cat > "${VERIFY_ROOT}/usr/lib/systemd/system/sysinit.target" <<'EOF'
[Unit]
Description=Stub sysinit target for package-root verification
EOF
  cat > "${VERIFY_ROOT}/usr/lib/systemd/system/network.target" <<'EOF'
[Unit]
Description=Stub network target for package-root verification
EOF
  cat > "${VERIFY_ROOT}/usr/lib/systemd/system/network-online.target" <<'EOF'
[Unit]
Description=Stub network-online target for package-root verification
After=network.target
Wants=network.target
EOF
  cat > "${VERIFY_ROOT}/usr/lib/systemd/system/multi-user.target" <<'EOF'
[Unit]
Description=Stub multi-user target for package-root verification
After=sysinit.target
EOF

  systemd-analyze verify --root="${VERIFY_ROOT}" \
    "${VERIFY_ROOT}/usr/lib/systemd/system/aegis-server.service" \
    "${VERIFY_ROOT}/usr/lib/systemd/system/aegis-client.service" >/dev/null
fi

echo "PASS: package-root contract"
