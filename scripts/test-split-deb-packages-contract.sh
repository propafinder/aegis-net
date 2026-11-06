#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
export PATH="${HOME}/.cargo/bin:${PATH}"

if ! command -v dpkg-deb >/dev/null 2>&1; then
  echo "dpkg-deb is required" >&2
  exit 1
fi

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/aegis-split-deb-contract.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT

# These packages are built and inspected only on the current contract host.
# shellcheck source=scripts/lib/test-host-release-abi.sh
. "${ROOT}/scripts/lib/test-host-release-abi.sh"
aegis_test_use_host_release_abi "split-deb-packages contract"
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
SERVER_SHA="${SERVER_DEB}.sha256"
CLIENT_SHA="${CLIENT_DEB}.sha256"
MANIFEST_PATH="${TMP_DIR}/split-deb-packages.manifest.json"

SERVER_EXTRACT="${TMP_DIR}/server-extract"
SERVER_CTRL="${TMP_DIR}/server-control"
CLIENT_EXTRACT="${TMP_DIR}/client-extract"
CLIENT_CTRL="${TMP_DIR}/client-control"

python3 -I -B "${ROOT}/scripts/verify-deb-archive-ownership.py" "${SERVER_DEB}"
python3 -I -B "${ROOT}/scripts/verify-deb-archive-ownership.py" "${CLIENT_DEB}"

dpkg-deb -x "${SERVER_DEB}" "${SERVER_EXTRACT}"
dpkg-deb -e "${SERVER_DEB}" "${SERVER_CTRL}"
dpkg-deb -x "${CLIENT_DEB}" "${CLIENT_EXTRACT}"
dpkg-deb -e "${CLIENT_DEB}" "${CLIENT_CTRL}"

# The split client must carry the exact protected helpers and static AUTO
# units from the canonical package-root. Archive ownership was checked above;
# compare the installed bytes, modes and conffile policy as well.
python3 -I -B - "${ROOT}" "${SERVER_EXTRACT}" "${SERVER_CTRL}" "${CLIENT_EXTRACT}" "${CLIENT_CTRL}" <<'PY'
import re
import stat
import sys
from pathlib import Path

root, server_extract, server_ctrl, client_extract, client_ctrl = map(Path, sys.argv[1:])

def roster(source: Path, name: str) -> tuple[str, ...]:
    body = source.read_text()
    block = re.search(r'^' + re.escape(name) + r'=\(\n(.*?)^\)', body,
                      re.MULTILINE | re.DOTALL)
    assert block is not None, name
    result = []
    for line in block.group(1).splitlines():
        entry = re.fullmatch(r'\s+"([A-Za-z0-9_./@-]+)"', line)
        assert entry is not None, (name, line)
        value = entry.group(1)
        assert not value.startswith('/') and '..' not in Path(value).parts, value
        result.append(value)
    result = tuple(result)
    assert result and len(result) == len(set(result)), name
    return result

package_root = root / 'scripts/build-package-root.sh'
split = root / 'scripts/build-split-deb-packages.sh'
helpers = roster(package_root, 'WIDE_HELPER_SCRIPTS')
units = roster(package_root, 'AUTO_SYSTEMD_UNITS')
server_helpers = roster(split, 'SERVER_HELPER_PATHS')
helper_paths = tuple('usr/local/lib/aegis/helpers/' + name for name in helpers)
unit_paths = tuple('etc/systemd/system/' + name for name in units)
shutdown_hook = 'usr/local/lib/aegis/helpers/lib/aegis-auto-terminal-hook'
split_helpers = roster(split, 'CLIENT_PROTECTED_HELPER_PATHS')
assert split_helpers.count(shutdown_hook) == 1
assert tuple(path for path in split_helpers if path != shutdown_hook) == helper_paths
assert roster(split, 'CLIENT_AUTO_UNIT_PATHS') == unit_paths
assert len(helpers) == 33 and len(split_helpers) == 34 and len(units) == 16
for name in ('lib/aegis_auto_foreign_policy.py', 'lib/aegis_auto_foreign_monitor.py',
             'lib/aegis_auto_ufw_pins.json', 'lib/aegis_initrd_policy.py',
             'lib/aegis_auto_uninstall_journal.py', 'lib/aegis_initrd_classic.py',
             'lib/aegis_auto_terminal_witness.py', 'lib/aegis_auto_terminal_boot_store.py',
             'lib/aegis_auto_terminal_register.py', 'lib/aegis_auto_boot_transition.py'):
    assert name in helpers, name
assert 'aegis-foreign-policy-monitor.service' in units
assert 'aegis-auto-clean-shutdown.service' in units
assert 'aegis-device-dhcp-refresh.service' in units
assert 'aegis-device-dhcp-refresh.timer' in units
for name in ('aegis-auto-terminal-a@.service', 'aegis-auto-terminal-b@.service',
             'aegis-auto-terminal-observer.service', 'aegis-auto-terminal-transition.service'):
    assert name in units, name
assert 'usr/share/aegis/scripts/lib/root-state.sh' in server_helpers

for relative in server_helpers:
    installed = server_extract / relative
    source = root / relative.removeprefix('usr/share/aegis/')
    info = installed.lstat()
    assert stat.S_ISREG(info.st_mode) and info.st_nlink == 1, relative
    assert stat.S_IMODE(info.st_mode) == 0o755, relative
    assert installed.read_bytes() == source.read_bytes(), relative

for name, relative in zip(helpers, helper_paths):
    installed = client_extract / relative
    source = root / 'scripts' / name
    info = installed.lstat()
    expected_mode = 0o500 if (name.startswith('lib/aegis_auto_') or name in ('lib/aegis_installer_auto_v2.py','lib/aegis_initrd_policy.py','lib/aegis_initrd_classic.py')) else 0o755
    assert stat.S_ISREG(info.st_mode) and info.st_nlink == 1, relative
    assert stat.S_IMODE(info.st_mode) == expected_mode, relative
    assert installed.read_bytes() == source.read_bytes(), relative

installed_hook = client_extract / shutdown_hook
hook_info = installed_hook.lstat()
assert stat.S_ISREG(hook_info.st_mode) and hook_info.st_nlink == 1, shutdown_hook
assert stat.S_IMODE(hook_info.st_mode) == 0o500, shutdown_hook
assert installed_hook.read_bytes() == (root / 'packaging/systemd/system-shutdown/aegis-auto-terminal-hook').read_bytes()

for name, relative in zip(units, unit_paths):
    installed = client_extract / relative
    source = root / 'packaging/systemd' / name
    info = installed.lstat()
    assert stat.S_ISREG(info.st_mode) and info.st_nlink == 1, relative
    assert stat.S_IMODE(info.st_mode) == 0o644, relative
    assert installed.read_bytes() == source.read_bytes(), relative

tmpfiles = [line.split() for line in (client_extract / 'usr/lib/tmpfiles.d/aegis-client.conf').read_text().splitlines()]
for path in ('/var/lib/aegis-client', '/etc/aegis/client'):
    assert [row for row in tmpfiles if row[1] == path] == [['d', path, '-', '-', '-', '-']]
assert ['d', '/var/log/aegis-client', '0755', 'root', 'root', '-'] in tmpfiles

assert (client_ctrl / 'conffiles').read_bytes() == b'/etc/default/aegis-client\n'
assert (server_ctrl / 'conffiles').read_bytes() == b'/etc/default/aegis-server\n'

client_deps = (client_ctrl / 'control').read_text()
server_deps = (server_ctrl / 'control').read_text()
assert 'python3 (>= 3.11)' in client_deps
assert 'python3 (>= 3.11)' in server_deps
for name in ('bash', 'coreutils', 'iproute2', 'iptables', 'nftables', 'util-linux'):
    assert name in client_deps, name
assert 'openssl' in server_deps

postinst = (client_ctrl / 'postinst').read_text()
assert 'systemctl preset aegis-client.service' in postinst
assert 'systemctl preset aegis-auto-' not in postinst
PY

check_split_deb_contract() {
cargo run --locked -q -p aegis-measure -- check-split-deb-package-contract-artifacts \
  --server-deb "${SERVER_DEB}" \
  --client-deb "${CLIENT_DEB}" \
  --server-sha256-path "${SERVER_SHA}" \
  --client-sha256-path "${CLIENT_SHA}" \
  --manifest-path "${MANIFEST_PATH}" \
  --server-extract-dir "${SERVER_EXTRACT}" \
  --server-control-dir "${SERVER_CTRL}" \
  --client-extract-dir "${CLIENT_EXTRACT}" \
  --client-control-dir "${CLIENT_CTRL}" \
  --version "${VERSION}" \
  --deb-arch "${DEB_ARCH}"
}

check_split_deb_contract

# A missing entry, extra entry, or whitespace change must fail the production
# checker for either package. Keep the actual DEBs/sidecars unchanged.
for role in client server; do
  control_dir="${CLIENT_CTRL}"
  if [[ "${role}" == server ]]; then control_dir="${SERVER_CTRL}"; fi
  cp "${control_dir}/conffiles" "${TMP_DIR}/${role}-conffiles.expected"
  for defect in missing-entry extra-entry trailing-space extra-newline missing-newline; do
  python3 -I -B - "${TMP_DIR}/${role}-conffiles.expected" "${control_dir}/conffiles" "${defect}" <<'PY'
from pathlib import Path
import sys
expected, actual = map(Path, sys.argv[1:3])
text = expected.read_text()
defect = sys.argv[3]
if defect == 'missing-entry':
    text = ''
elif defect == 'extra-entry':
    text += '/etc/aegis/unexpected.conf\n'
elif defect == 'trailing-space':
    text = text.replace('\n', ' \n')
elif defect == 'extra-newline':
    text += '\n'
elif defect == 'missing-newline':
    text = text.removesuffix('\n')
else:
    raise AssertionError(defect)
actual.write_text(text)
PY
  if check_split_deb_contract >"${TMP_DIR}/negative-${role}-${defect}.log" 2>&1; then
    echo "split DEB checker accepted ${role} ${defect} conffiles" >&2
    exit 1
  fi
  grep -F 'conffiles must equal' "${TMP_DIR}/negative-${role}-${defect}.log" >/dev/null
  done
  cp "${TMP_DIR}/${role}-conffiles.expected" "${control_dir}/conffiles"
done

if command -v systemd-analyze >/dev/null 2>&1; then
  SERVER_VERIFY="${TMP_DIR}/server-verify-root"
  CLIENT_VERIFY="${TMP_DIR}/client-verify-root"
  cp -R "${SERVER_EXTRACT}/." "${SERVER_VERIFY}"
  cp -R "${CLIENT_EXTRACT}/." "${CLIENT_VERIFY}"

  for verify_root in "${SERVER_VERIFY}" "${CLIENT_VERIFY}"; do
    mkdir -p "${verify_root}/usr/lib/systemd/system"
    cat > "${verify_root}/usr/lib/systemd/system/sysinit.target" <<'EOF'
[Unit]
Description=Stub sysinit target for split deb verification
EOF
    cat > "${verify_root}/usr/lib/systemd/system/network.target" <<'EOF'
[Unit]
Description=Stub network target for split deb verification
EOF
    cat > "${verify_root}/usr/lib/systemd/system/network-online.target" <<'EOF'
[Unit]
Description=Stub network-online target for split deb verification
After=network.target
Wants=network.target
EOF
    cat > "${verify_root}/usr/lib/systemd/system/multi-user.target" <<'EOF'
[Unit]
Description=Stub multi-user target for split deb verification
After=sysinit.target
EOF
  done

  systemd-analyze verify --root="${SERVER_VERIFY}" \
    "${SERVER_VERIFY}/usr/lib/systemd/system/aegis-server.service" >/dev/null
  systemd-analyze verify --root="${CLIENT_VERIFY}" \
    "${CLIENT_VERIFY}/usr/lib/systemd/system/aegis-client.service" >/dev/null
fi

echo "PASS: split deb packages contract"
