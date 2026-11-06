#!/usr/bin/env bash
set -euo pipefail
umask 022

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
export PATH="${HOME}/.cargo/bin:${PATH}"

usage() {
  cat <<'EOF'
Usage:
  scripts/build-split-deb-packages.sh <output-dir> [--debian-revision <positive-integer>]

Builds role-specific Debian packages on top of the canonical package-root:
  <output-dir>/aegis-server_<upstream-version>[-<debian-revision>]_<arch>.deb
  <output-dir>/aegis-client_<upstream-version>[-<debian-revision>]_<arch>.deb

This is the next Debian ergonomics layer over the combined baseline package.
EOF
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

if [[ $# -ne 1 && ! ( $# -eq 3 && "$2" == "--debian-revision" ) ]]; then
  usage >&2
  exit 1
fi

DEBIAN_REVISION=""
if [[ $# -eq 3 ]]; then
  DEBIAN_REVISION="$3"
  # A revision changes Debian package ordering, not the Cargo upstream version.
  if [[ ! "${DEBIAN_REVISION}" =~ ^[1-9][0-9]{0,17}$ ]]; then
    echo "Debian revision must be a canonical positive integer (at most 18 digits)" >&2
    exit 1
  fi
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
UPSTREAM_VERSION="$(printf '%s\n' "${META}" | sed -n '2p')"
VERSION="${UPSTREAM_VERSION}"
if [[ -n "${DEBIAN_REVISION}" ]]; then
  VERSION="${VERSION}-${DEBIAN_REVISION}"
fi

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/aegis-split-deb-build.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT

"${ROOT}/scripts/build-package-root.sh" "${TMP_DIR}" >/dev/null

PACKAGE_ROOT_DIR="${TMP_DIR}/aegis-package-root-${UPSTREAM_VERSION}-linux-${ARCH}"
ROOTFS_DIR="${PACKAGE_ROOT_DIR}/rootfs"
PROJECT_LICENSE_PATHS=(
  "usr/share/doc/aegis/LICENSE-MIT"
  "usr/share/doc/aegis/LICENSE-APACHE"
  "usr/share/doc/aegis/NOTICE"
  "usr/share/doc/aegis/THIRD-PARTY-NOTICES"
)
H2_LICENSE_PATH="usr/share/doc/aegis/third-party/h2/LICENSE"
TUNGSTENITE_LICENSE_PATHS=(
  "usr/share/doc/aegis/third-party/tungstenite/LICENSE-MIT"
  "usr/share/doc/aegis/third-party/tungstenite/LICENSE-APACHE"
)
SERVER_HELPER_PATHS=(
  "usr/share/aegis/scripts/lib/root-state.sh"
  "usr/share/aegis/scripts/bootstrap-wide-linux-validation-host.sh"
  "usr/share/aegis/scripts/generate-relay-materials.sh"
  "usr/share/aegis/scripts/render-client-bundle.sh"
  "usr/share/aegis/scripts/package-client-bundle.sh"
  "usr/share/aegis/scripts/issue-fronted-bundle.sh"
  "usr/share/aegis/scripts/aegis-wide-enable.sh"
  "usr/share/aegis/scripts/aegis-wide-disable.sh"
  "usr/share/aegis/scripts/aegis-wide-persist-install.sh"
  "usr/share/aegis/scripts/janitor-wide-linux-tproxy.sh"
  "usr/share/aegis/scripts/setup-wide-linux-redirect.sh"
  "usr/share/aegis/scripts/setup-wide-linux-tproxy.sh"
  "usr/share/aegis/scripts/validate-debian-package-host.sh"
  "usr/share/aegis/scripts/verify-deb-archive-ownership.py"
  "usr/share/aegis/scripts/verify-split-deb-package-set.py"
  "usr/share/aegis/scripts/build-ubuntu-controlled-pilot-playbook.sh"
  "usr/share/aegis/scripts/build-ubuntu-operator-reapply-canary.sh"
  "usr/share/aegis/scripts/build-ubuntu-controlled-pilot-bundle.sh"
  "usr/share/aegis/scripts/build-ubuntu-release-review.sh"
  "usr/share/aegis/scripts/build-ubuntu-controlled-pilot-review-bundle.sh"
  "usr/share/aegis/scripts/ubuntu-release-wave-status.sh"
  "usr/share/aegis/scripts/build-ubuntu-release-wave-bundle.sh"
  "usr/share/aegis/scripts/build-ubuntu-field-pilot-remote-bundle.sh"
  "usr/share/aegis/scripts/build-post-release-stealth-wave-summary.sh"
  "usr/share/aegis/scripts/mimicry-wire-validation-contract.sh"
  "usr/share/aegis/scripts/build-mimicry-wire-witness-summary.sh"
  "usr/share/aegis/scripts/validate-mimicry-wire-host.sh"
  "usr/share/aegis/scripts/build-ubuntu-mimicry-next-contour.sh"
)
CLIENT_PROTECTED_HELPER_PATHS=(
  "usr/local/lib/aegis/helpers/lib/root-state.sh"
  "usr/local/lib/aegis/helpers/lib/aegis_installer_auto_v2.py"
  "usr/local/lib/aegis/helpers/lib/aegis_auto_uninstall_journal.py"
  "usr/local/lib/aegis/helpers/lib/aegis_auto_capture.py"
  "usr/local/lib/aegis/helpers/lib/aegis_auto_capture_topology.py"
  "usr/local/lib/aegis/helpers/lib/aegis_auto_endpoint.py"
  "usr/local/lib/aegis/helpers/lib/aegis_auto_guard_policy.py"
  "usr/local/lib/aegis/helpers/lib/aegis_auto_foreign_policy.py"
  "usr/local/lib/aegis/helpers/lib/aegis_auto_foreign_monitor.py"
  "usr/local/lib/aegis/helpers/lib/aegis_auto_ufw_pins.json"
  "usr/local/lib/aegis/helpers/lib/aegis_initrd_policy.py"
  "usr/local/lib/aegis/helpers/lib/aegis_initrd_classic.py"
  "usr/local/lib/aegis/helpers/lib/aegis_auto_guardian.py"
  "usr/local/lib/aegis/helpers/lib/aegis_auto_guardian_watchdog.py"
  "usr/local/lib/aegis/helpers/lib/aegis_auto_terminal_witness.py"
  "usr/local/lib/aegis/helpers/lib/aegis_auto_terminal_boot_store.py"
  "usr/local/lib/aegis/helpers/lib/aegis_auto_terminal_register.py"
  "usr/local/lib/aegis/helpers/lib/aegis_auto_boot_transition.py"
  "usr/local/lib/aegis/helpers/lib/aegis-auto-terminal-hook"
  "usr/local/lib/aegis/helpers/lib/aegis_auto_launch.py"
  "usr/local/lib/aegis/helpers/lib/aegis_auto_native_witness.py"
  "usr/local/lib/aegis/helpers/lib/aegis_auto_sink.py"
  "usr/local/lib/aegis/helpers/lib/aegis_auto_trace_rollback.py"
  "usr/local/lib/aegis/helpers/lib/aegis_auto_witness_topology.py"
  "usr/local/lib/aegis/helpers/aegis-device-egress-guard.sh"
  "usr/local/lib/aegis/helpers/purge-installed-aegis.sh"
  "usr/local/lib/aegis/helpers/aegis-ubuntu-uninstall.sh"
  "usr/local/lib/aegis/helpers/aegis-wide-enable.sh"
  "usr/local/lib/aegis/helpers/aegis-wide-disable.sh"
  "usr/local/lib/aegis/helpers/aegis-wide-persist-install.sh"
  "usr/local/lib/aegis/helpers/janitor-wide-linux-tproxy.sh"
  "usr/local/lib/aegis/helpers/setup-wide-linux-redirect.sh"
  "usr/local/lib/aegis/helpers/setup-wide-linux-tproxy.sh"
  "usr/local/lib/aegis/helpers/setup-wide-linux-nfqueue.sh"
)
CLIENT_AUTO_UNIT_PATHS=(
  "etc/systemd/system/aegis-auto-config.service"
  "etc/systemd/system/aegis-auto-capture-topology.service"
  "etc/systemd/system/aegis-auto-guardian-watchdog.service"
  "etc/systemd/system/aegis-auto-guardian.service"
  "etc/systemd/system/aegis-auto-terminal-a@.service"
  "etc/systemd/system/aegis-auto-terminal-b@.service"
  "etc/systemd/system/aegis-auto-terminal-observer.service"
  "etc/systemd/system/aegis-auto-terminal-transition.service"
  "etc/systemd/system/aegis-auto-trace-rollback-actor.service"
  "etc/systemd/system/aegis-auto-trace-rollback.service"
  "etc/systemd/system/aegis-auto-trace-rollback.timer"
  "etc/systemd/system/aegis-auto-witness-topology.service"
  "etc/systemd/system/aegis-foreign-policy-monitor.service"
  "etc/systemd/system/aegis-auto-clean-shutdown.service"
  "etc/systemd/system/aegis-device-dhcp-refresh.service"
  "etc/systemd/system/aegis-device-dhcp-refresh.timer"
)

mkdir -p "${OUTPUT_DIR}"
UNVERIFIED_DIR="$(mktemp -d "${OUTPUT_DIR}/.aegis-split-deb-unverified.XXXXXX")"
trap 'rm -rf -- "${TMP_DIR}" "${UNVERIFIED_DIR}"' EXIT

copy_rootfs_file() {
  local rel="$1"
  local stage_dir="$2"
  local destination="${3:-${rel}}"
  mkdir -p "${stage_dir}/$(dirname "${destination}")"
  cp --preserve=mode "${ROOTFS_DIR}/${rel}" "${stage_dir}/${destination}"
}

write_control() {
  local path="$1"
  local package_name="$2"
  local description="$3"
  local dependencies="systemd, ca-certificates, bash, coreutils, iproute2, iptables, nftables, util-linux, python3"
  dependencies="${dependencies} (>= 3.11)"
  if [[ "${package_name}" == "aegis-server" ]]; then
    dependencies="${dependencies}, openssl"
  fi
  cat > "${path}" <<EOF
Package: ${package_name}
Version: ${VERSION}
Section: net
Priority: optional
Architecture: ${DEB_ARCH}
Maintainer: AEGIS Packaging <packaging@aegis.invalid>
Depends: ${dependencies}
Description: ${description}
 Role-specific Debian package generated from the canonical AEGIS package-root
 staging layout.
EOF
}

# Removal hooks authenticate their own source bytes from the build-time
# protected roster. postrm uses retained source after dpkg removes helpers.
write_client_removal_hook() {
  local path="$1" operation="$2"
  cat > "$path" <<'PY_REMOVAL'
#!/usr/bin/python3 -I
"""Authenticated passive-package handoff; active AUTO keeps its typed journal."""
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import types

EXPECTED = json.loads(AEGIS_INCOMING_ROSTER_JSON)
HOOK = 'AEGIS_REMOVAL_HOOK'


def need(value):
    if not value:
        raise ValueError('AEGIS AUTO owner requires typed serial teardown; package removal refused')


def source_bytes(path, mode, expected):
    parent = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        for part in path.parts[1:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                            dir_fd=parent)
            info = os.fstat(child)
            need(info.st_uid == info.st_gid == 0 and not stat.S_IMODE(info.st_mode) & 0o022)
            os.close(parent)
            parent = child
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                     dir_fd=parent)
        try:
            before = os.fstat(fd)
            need(stat.S_ISREG(before.st_mode) and before.st_uid == before.st_gid == 0 and
                 before.st_nlink == 1 and stat.S_IMODE(before.st_mode) == mode and
                 0 < before.st_size <= 4 << 20)
            raw = os.read(fd, (4 << 20) + 1)
            after = os.fstat(fd)
            named = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
            need(len(raw) == before.st_size and hashlib.sha256(raw).hexdigest() == expected and
                 all(getattr(before, key) == getattr(after, key) for key in (
                     'st_dev', 'st_ino', 'st_size', 'st_mode', 'st_nlink', 'st_mtime_ns', 'st_ctime_ns')) and
                 (named.st_dev, named.st_ino) == (before.st_dev, before.st_ino))
            return raw
        finally:
            os.close(fd)
    finally:
        os.close(parent)


def postrm_cleanup(action):
    if action == 'purge' and Path('/usr/bin/systemd-tmpfiles').is_file():
        subprocess.run(['/usr/bin/systemd-tmpfiles', '--remove',
                        '/usr/lib/tmpfiles.d/aegis-client.conf'], timeout=15,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
    if Path('/usr/bin/systemctl').is_file():
        subprocess.run(['/usr/bin/systemctl', 'daemon-reload'], timeout=15,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)


def main():
    action = sys.argv[1] if len(sys.argv) > 1 else ''
    if action not in (('remove', 'deconfigure') if HOOK == 'prerm' else ('remove', 'purge')):
        return
    # Deconfiguration does not imply package deletion and has no matching
    # removal completion. Refuse before publishing intent or stopping a unit.
    need(not (HOOK == 'prerm' and action == 'deconfigure'))
    need(sys.platform == 'linux' and os.geteuid() == 0)
    journal = Path('/var/lib/aegis-auto-uninstall')
    if HOOK == 'postrm' and not journal.exists() and not journal.is_symlink():
        postrm_cleanup(action)
        return
    sources = {}
    for name in ('aegis_installer_auto_v2.py', 'aegis_auto_uninstall_journal.py'):
        relative = 'usr/local/lib/aegis/helpers/lib/' + name
        path = Path('/' + relative)
        mode = 0o500
        if HOOK == 'postrm' and not path.exists() and not path.is_symlink():
            path = journal / 'recovery' / name
            mode = 0o600
        sources[name] = (path, source_bytes(path, mode, EXPECTED['files'][relative]['sha256']))
    modules = {}
    for name in ('aegis_auto_uninstall_journal.py', 'aegis_installer_auto_v2.py'):
        path, raw = sources[name]
        module = types.ModuleType('aegis_verified_' + name.removesuffix('.py'))
        module.__file__ = str(path)
        exec(compile(raw, str(path), 'exec'), module.__dict__)
        modules[name] = module
    coordinator = modules['aegis_installer_auto_v2.py']
    coordinator.uninstall_journal.module = modules['aegis_auto_uninstall_journal.py']
    if HOOK == 'prerm':
        result = coordinator.passive_package_prerm(EXPECTED)
        if result['state'] != 'active-package-handoff':
            coordinator.call_output(['/usr/bin/systemctl', '--no-reload', 'disable', '--now',
                                     'aegis-client.service'], maximum=4096, timeout=30)
            coordinator._passive_removal_no_owner()
            coordinator._passive_removal_actors()
            coordinator._passive_removal_recheck_payload(EXPECTED)
    else:
        coordinator.passive_package_postrm(EXPECTED, action)
        postrm_cleanup(action)


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        source, line = 'hook', 0
        trace = error.__traceback__
        while trace:
            name = Path(trace.tb_frame.f_code.co_filename).name
            if name in ('aegis_installer_auto_v2.py', 'aegis_auto_uninstall_journal.py'):
                source, line = name, trace.tb_lineno
            trace = trace.tb_next
        line = line if 0 <= line <= 10000 else 0
        kind = type(error).__name__
        kind = kind if kind in ('Refused', 'OSError', 'ValueError', 'KeyError', 'TypeError',
                               'FileNotFoundError', 'PermissionError') else 'error'
        print('AEGIS AUTO owner requires typed serial teardown or passive removal recovery; refused',
              file=sys.stderr)
        print('AEGIS_PACKAGE_REMOVAL_REFUSED source=%s line=%d class=%s' % (source, line, kind),
              file=sys.stderr)
        sys.exit(1)
PY_REMOVAL
  python3 -I -B - "$path" "$operation" <<'PY'
from pathlib import Path
import sys
path = Path(sys.argv[1])
assert sys.argv[2] in ('prerm', 'postrm')
body = path.read_text()
assert body.count('AEGIS_REMOVAL_HOOK') == 1
path.write_text(body.replace('AEGIS_REMOVAL_HOOK', sys.argv[2]))
PY
  chmod 0755 "$path"
}

# The client preinst runs while the old installed helper and binary still
# exist.  Embed the exact incoming protected payload, so a V2 successor for a
# different release cannot authorize dpkg to replace these files.
write_client_upgrade_roster() {
  local stage_dir="$1" debian_dir="$2"
  python3 -I -B - "$ROOT" "$stage_dir" "$debian_dir" "$VERSION" <<'PY'
import hashlib
import json
import pathlib
import re
import stat
import sys

source, staged, debian = map(pathlib.Path, sys.argv[1:4])
builder = (source / 'scripts/build-split-deb-packages.sh').read_text()
def roster(name):
    match = re.search(r'^' + re.escape(name) + r'=\(\n(.*?)^\)', builder,
                      re.MULTILINE | re.DOTALL)
    assert match is not None
    result = re.findall(r'^\s+"([A-Za-z0-9_./@-]+)"$', match.group(1), re.MULTILINE)
    assert result and len(result) == len(set(result))
    return result

paths = ['usr/local/bin/aegis-client', *roster('CLIENT_PROTECTED_HELPER_PATHS'),
         *roster('CLIENT_AUTO_UNIT_PATHS')]
manifest = {}
for relative in paths:
    file = staged / relative
    assert file.is_file() and not file.is_symlink()
    if relative == 'usr/local/bin/aegis-client':
        original = file
    elif relative == 'usr/local/lib/aegis/helpers/lib/aegis-auto-terminal-hook':
        original = source / 'packaging/systemd/system-shutdown/aegis-auto-terminal-hook'
    elif relative.startswith('usr/local/lib/aegis/helpers/'):
        original = source / 'scripts' / relative.removeprefix('usr/local/lib/aegis/helpers/')
    else:
        original = source / 'packaging/systemd' / relative.removeprefix('etc/systemd/system/')
    assert original.is_file() and not original.is_symlink()
    # Match auto_v2_retain_public_payload: policy modules are data even
    # when a Git/release archive marks their original source executable.
    policy_data = (relative.startswith('usr/local/lib/aegis/helpers/lib/') and
                   relative.endswith(('.py', '.json')))
    manifest[relative] = {'sha256': hashlib.sha256(file.read_bytes()).hexdigest(),
                          'mode': stat.S_IMODE(file.stat().st_mode),
                          'retained_mode': (0o444 if policy_data else
                                            (0o555 if original.stat().st_mode & 0o111 else 0o444))}
install = hashlib.sha256((source / 'install.sh').read_bytes()).hexdigest()
data = json.dumps({'files': manifest, 'install_sha256': install},
                  sort_keys=True, separators=(',', ':'))
for name in ('preinst', 'postinst', 'prerm', 'postrm'):
    path = debian / name
    body = path.read_text()
    assert body.count('AEGIS_INCOMING_ROSTER_JSON') == 1
    selected = (json.dumps({'files': manifest, 'install_sha256': install,
                           'package_version': sys.argv[4]}, sort_keys=True, separators=(',', ':'))
                if name in ('prerm', 'postrm') else data)
    path.write_text(body.replace('AEGIS_INCOMING_ROSTER_JSON', repr(selected)))
PY
}

write_client_preinst() {
  local path="$1"
  cat > "$path" <<'PY'
#!/usr/bin/python3 -I
"""Refuse V2 package replacement without the old source's stopped successor."""
import hashlib
import json
import os
import pathlib
import re
import stat
import subprocess
import sys
import ctypes
import secrets

EXPECTED = json.loads(AEGIS_INCOMING_ROSTER_JSON)

def need(value):
    if not value:
        raise ValueError('protected V2 package transition refused')

def held(path, mode=None):
    parts = pathlib.Path(path).parts
    need(parts and parts[0] == '/' and all(part not in ('.', '..') for part in parts))
    parent = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for part in parts[1:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW |
                            os.O_CLOEXEC, dir_fd=parent)
            info = os.fstat(child)
            try:
                need(stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == 0 and
                     not stat.S_IMODE(info.st_mode) & 0o022)
            except BaseException:
                os.close(child)
                raise
            os.close(parent)
            parent = child
        fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC |
                     os.O_NONBLOCK, dir_fd=parent)
        info = os.fstat(fd)
        try:
            need(stat.S_ISREG(info.st_mode) and info.st_uid == info.st_gid == 0 and
                 info.st_nlink == 1 and info.st_size <= 512 * 1024 * 1024 and
                 (mode is None or stat.S_IMODE(info.st_mode) == mode))
            return fd
        except BaseException:
            os.close(fd)
            raise
    finally:
        os.close(parent)

def control_present():
    parent = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for part in ('var', 'lib', 'aegis-auto', 'control'):
            try:
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY |
                                os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
            except FileNotFoundError:
                return False
            info = os.fstat(child)
            try:
                need(stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == 0 and
                     not stat.S_IMODE(info.st_mode) & 0o022 and
                     (part != 'control' or stat.S_IMODE(info.st_mode) == 0o700))
            except BaseException:
                os.close(child)
                raise
            os.close(parent)
            parent = child
        return bool(os.listdir(parent))
    finally:
        os.close(parent)

def digest(fd):
    value = hashlib.sha256()
    while chunk := os.read(fd, 65536):
        value.update(chunk)
    return value.hexdigest()

def anchored_digest(path):
    # The old native successor commits these source bytes before package effect.
    fd = held(path, 0o444)
    try:
        before = os.fstat(fd)
        need(0 < before.st_size <= 4 * 1024 * 1024)
        value = digest(fd)
        after = os.fstat(fd)
        named = os.stat(path, follow_symlinks=False)
        keys = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid',
                'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
        need(all(getattr(before, key) == getattr(after, key) ==
                 getattr(named, key) for key in keys))
        return value
    finally:
        os.close(fd)

def incoming_source(root):
    for relative, expected in EXPECTED['files'].items():
        if relative == 'usr/local/bin/aegis-client':
            retained = root + '/bin/aegis-client'
        elif relative == 'usr/local/lib/aegis/helpers/lib/aegis-auto-terminal-hook':
            retained = root + '/packaging/systemd/system-shutdown/aegis-auto-terminal-hook'
        elif relative.startswith('usr/local/lib/aegis/helpers/'):
            retained = root + '/scripts/' + relative.removeprefix('usr/local/lib/aegis/helpers/')
        elif relative.startswith('etc/systemd/system/'):
            retained = root + '/packaging/systemd/' + relative.removeprefix('etc/systemd/system/')
        else:
            need(False)
        fd = held(retained, expected['retained_mode'])
        try:
            need(digest(fd) == expected['sha256'])
        finally:
            os.close(fd)

def private_json(path, maximum):
    fd = held(path, 0o600)
    try:
        before = os.fstat(fd)
        need(0 < before.st_size <= maximum)
        raw = os.read(fd, maximum + 1)
        after = os.fstat(fd)
        need(len(raw) == before.st_size and raw.endswith(b'\n') and
             (before.st_dev, before.st_ino, before.st_size, before.st_ctime_ns) ==
             (after.st_dev, after.st_ino, after.st_size, after.st_ctime_ns))
    finally:
        os.close(fd)
    row = json.loads(raw, object_pairs_hook=lambda pairs:
                     dict(pairs) if len(dict(pairs)) == len(pairs) else need(False),
                     parse_constant=lambda _value:need(False))
    need(type(row) is dict and
         raw == (json.dumps(row, sort_keys=True, separators=(',', ':')) + '\n').encode('ascii'))
    return row, raw

def inherited_lock(fd, path):
    held_fd, named = os.fstat(fd), os.stat(path, follow_symlinks=False)
    need(stat.S_ISREG(held_fd.st_mode) and held_fd.st_uid == held_fd.st_gid == 0 and
         held_fd.st_nlink == 1 and stat.S_IMODE(held_fd.st_mode) == 0o600 and
         (held_fd.st_dev, held_fd.st_ino) == (named.st_dev, named.st_ino))
    fdinfo = pathlib.Path(f'/proc/self/fdinfo/{fd}').read_text(encoding='ascii')
    locks = [line.split() for line in fdinfo.splitlines() if line.startswith('lock:')]
    need(len(fdinfo) <= 4096 and len(locks) == 1 and len(locks[0]) == 9 and
         locks[0][0] == 'lock:' and
         re.fullmatch(r'[1-9][0-9]*:',locks[0][1]) and
         locks[0][2:5] == ['FLOCK', 'ADVISORY', 'WRITE'] and
         re.fullmatch(r'[0-9]+',locks[0][5]) and
         locks[0][7:] == ['0', 'EOF'])
    device = re.fullmatch(r'([0-9a-fA-F]+):([0-9a-fA-F]+):([0-9]+)',locks[0][6])
    need(device is not None and
         int(device[1],16) == os.major(held_fd.st_dev) and
         int(device[2],16) == os.minor(held_fd.st_dev) and
         int(device[3]) == held_fd.st_ino)

def cold_dir_fd(parts):
    parent = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for index,part in enumerate(parts):
            try:
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY |
                                os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
            except FileNotFoundError:
                return None
            try:
                info = os.fstat(child)
                need(stat.S_ISDIR(info.st_mode) and
                     info.st_uid == info.st_gid == 0 and
                     not stat.S_IMODE(info.st_mode) & 0o022 and
                     (index < 3 or
                      stat.S_IMODE(info.st_mode) == 0o700))
            except BaseException:
                os.close(child)
                raise
            os.close(parent)
            parent = child
        result = parent
        parent = None
        return result
    finally:
        if parent is not None:
            os.close(parent)

def cold_current_head():
    parent = ('/var/lib/aegis-install/client/terminal-migrations/'
              'cold-recovery/')
    parent_fd = cold_dir_fd(('var','lib','aegis-install','client',
                             'terminal-migrations','cold-recovery'))
    if parent_fd is None:
        return None
    boot = pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    need(re.fullmatch(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}',boot))
    try:
        names = os.listdir(parent_fd)
    finally:
        os.close(parent_fd)
    prefix = 'attempt-head-' + boot + '-'
    found = [name for name in names if name.startswith(prefix)]
    need(len(names) <= 512 and len(found) <= 1)
    if not found:
        return None
    need(re.fullmatch(r'attempt-head-' + boot + r'-[0-9a-f]{64}\.json',
                      found[0]))
    head,raw = private_json(parent + found[0],8192)
    need(set(head)=={'schema','current_boot_id','prior_boot_id',
                     'prior_intent_sha256','original_intent_sha256',
                     'barrier_sha256','attempt_intent_sha256','attempt_dir'} and
         head['schema']=='aegis_auto_terminal_cold_attempt_head_v1' and
         head['current_boot_id']==boot and
         head['attempt_intent_sha256']==found[0][-69:-5] and
         re.fullmatch(r'[0-9a-f]{64}',head['prior_intent_sha256']))
    phase=parent + 'attempts/' + boot + '-' + head['prior_intent_sha256'] + '/'
    need(head['attempt_dir']==phase[:-1])
    attempt_fd=cold_dir_fd(('var','lib','aegis-install','client',
        'terminal-migrations','cold-recovery','attempts',
        boot+'-'+head['prior_intent_sha256']))
    need(attempt_fd is not None)
    os.close(attempt_fd)
    return phase,head,hashlib.sha256(raw).hexdigest()

def cold_package_admit(selected=None):
    cold = (selected[0] if selected is not None else
            '/var/lib/aegis-install/client/terminal-migrations/cold-recovery/')
    intent, intent_raw = private_json(cold + 'intent.json', 8192)
    phase, phase_raw = private_json(cold + 'phase-01.json', 8192)
    boot = pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    root = intent.get('retained_root')
    intent_keys = {
        'schema','old_boot_id','current_boot_id','old_active_sha256',
        'old_stopped_sha256','successor_intent_sha256','old_install_sha256',
        'old_source_sha256','guardian_rotation_intent_sha256',
        'guardian_rotation_denied_sha256','guardian_rotation_retired_sha256',
        'retained_root','new_candidate_sha256','new_package_sha256',
        'selected_manager','manager31_sha256','guard30_sha256',
        'old_context_sha256','deny_policy_sha256',
        'initial_denied_proof_sha256','initial_infrastructure_rows_sha256',
        'next_bundle_manifest_sha256','next_sums_sha256',
    }
    need(set(intent) == intent_keys and
         intent.get('schema') == 'aegis_auto_terminal_cold_intent_v1' and
         type(root) is str and re.fullmatch(
             r'/var/lib/aegis-auto/releases/[A-Za-z0-9-]{16,128}',root) and
         intent.get('current_boot_id') == boot and
         type(intent.get('old_boot_id')) is str and
         intent['old_boot_id'] != boot and
         intent.get('new_candidate_sha256') ==
             EXPECTED['files']['usr/local/bin/aegis-client']['sha256'] and
         set(phase) == {'schema','intent_sha256','deny_policy_sha256',
                        'pre_quiesce_infrastructure_sha256',
                        'post_quiesce_infrastructure_sha256',
                        'quiesce_monotonic_tick'} and
         phase.get('schema')=='aegis_auto_terminal_cold_deny_v2' and
         phase.get('intent_sha256')==hashlib.sha256(intent_raw).hexdigest() and
         phase.get('deny_policy_sha256')==intent.get('deny_policy_sha256') and
         phase.get('pre_quiesce_infrastructure_sha256')==
             intent.get('initial_infrastructure_rows_sha256') and
         type(phase.get('post_quiesce_infrastructure_sha256')) is str and
         re.fullmatch(r'[0-9a-f]{64}',
                      phase['post_quiesce_infrastructure_sha256']) and
         type(phase.get('quiesce_monotonic_tick')) is int and
         phase['quiesce_monotonic_tick'] > 0)
    inherited_lock(9, '/run/aegis-auto-install.lock')
    inherited_lock(10, '/var/lib/aegis-install/client/device-guard.conf.lock')
    candidate = root + '/bin/aegis-client'
    fd = held(candidate, 0o555)
    try:
        need(digest(fd) == intent['new_candidate_sha256'])
    finally:
        os.close(fd)
    need(anchored_digest(root + '/bundle.manifest.json') ==
         intent['next_bundle_manifest_sha256'] and
         anchored_digest(root + '/SHA256SUMS') == intent['next_sums_sha256'])
    incoming_source(root)
    result = subprocess.run(
        [candidate, 'auto-verify-cold-retired-successor', '--lock-fd','9',
         '--guard-fd','10','--retained-root',root], pass_fds=(9,10),
        capture_output=True,timeout=90,check=False)
    need(result.returncode == 0 and not result.stderr and
         0 < len(result.stdout) <= 64 * 1024)
    proof = json.loads(result.stdout, object_pairs_hook=lambda pairs:
                       dict(pairs) if len(dict(pairs)) == len(pairs) else need(False))
    need(type(proof) is dict and
         proof.get('schema') == 'aegis_auto_v2_cold_retired_successor_v2' and
         proof.get('current_boot_id') == boot and
         proof.get('retained_root') == root and
         proof.get('new_candidate_sha256') == intent['new_candidate_sha256'] and
         proof.get('successor_intent_sha256') == intent['successor_intent_sha256'] and
         proof.get('cold_intent_sha256') == hashlib.sha256(intent_raw).hexdigest() and
         proof.get('deny_policy_sha256') == phase['deny_policy_sha256'] and
         proof.get('quiesce_state') == 'post' and
         proof.get('quiesce_receipt_sha256') ==
             hashlib.sha256(phase_raw).hexdigest() and
         proof.get('quiesce_monotonic_tick') ==
             phase['quiesce_monotonic_tick'] and
         proof.get('infrastructure_quiescent') is True and
         (proof.get('package_state')!='old_exact' or
          proof.get('infrastructure_rows_sha256') ==
              phase['post_quiesce_infrastructure_sha256']) and
         proof.get('package_state') in ('old_exact','known_interrupted') and
         (proof.get('migration_state')=='preparation_absent' and
          proof.get('site_state')=='a_exact' or
          proof.get('migration_state')=='pending_prefix' and
          proof.get('site_state') in
              ('a_exact','a_retiring_prefix','absent','b_prefix')) and
         proof.get('observer_state') == 'absent' and
         proof.get('infrastructure_qualified') is True and
         all(proof.get(key) is True for key in
             ('client_actors_absent','jobs_absent','cgroups_empty',
              'stop_intent_absent')) and
         (proof.get('migration_state') == 'preparation_absent' and
          proof.get('context_state') == 'absent_not_prepared' and
          proof.get('cold_context_state') == 'present_exact' or
          proof.get('migration_state') == 'pending_prefix' and
          proof.get('context_state') == 'present_exact' and
          proof.get('cold_context_state') == 'absent_not_prepared'))
    if selected is not None:
        head,head_sha=selected[1:]
        need(head['attempt_intent_sha256']==
             hashlib.sha256(intent_raw).hexdigest())
        checked=subprocess.run(
            [candidate,'auto-verify-cold-attempt-inherited',
             '--lock-fd','9','--guard-fd','10','--retained-root',root],
            pass_fds=(9,10),capture_output=True,timeout=90,check=False)
        need(checked.returncode==0 and not checked.stderr and
             0<len(checked.stdout)<=8192)
        attempt=json.loads(checked.stdout,object_pairs_hook=lambda pairs:
                 dict(pairs) if len(dict(pairs))==len(pairs) else need(False))
        need(type(attempt) is dict and
             attempt.get('schema')==
                 'aegis_auto_v2_cold_attempt_resolution_v1' and
             attempt.get('current_boot_id')==boot and
             attempt.get('attempt_dir')==cold[:-1] and
             attempt.get('attempt_intent_sha256')==
                 head['attempt_intent_sha256'] and
             attempt.get('attempt_head_sha256')==head_sha and
             attempt.get('no_client_grant') is True)
    inherited_lock(9, '/run/aegis-auto-install.lock')
    inherited_lock(10, '/var/lib/aegis-install/client/device-guard.conf.lock')
    need(private_json(cold + 'intent.json',8192)[1] == intent_raw and
         private_json(cold + 'phase-01.json',8192)[1] == phase_raw)
    if selected is not None:
        need(cold_current_head()==selected)

def main():
    need(os.geteuid() == 0 and sys.platform == 'linux')
    # A typed pre-Prepare abort may have already archived CONTROL while its
    # final receipt is still being sealed. Never unpack across that interval.
    need(not os.path.lexists('/var/lib/aegis-auto/fresh-passive-abort-current.json'))
    # A persistent uninstall intent is a package admission barrier even after
    # the ordinary V2 control tree has been archived.
    need(not os.path.lexists('/var/lib/aegis-auto-uninstall'))
    cold_intent = ('/var/lib/aegis-install/client/terminal-migrations/'
                   'cold-recovery/intent.json')
    current_attempt=cold_current_head()
    if current_attempt is not None:
        cold_package_admit(current_attempt)
        return
    if os.path.lexists(cold_intent):
        cold_package_admit()
        return
    cold_ready = ('/var/lib/aegis-install/client/terminal-migrations/'
                  'cold-recovery/transition-ready.json')
    if os.path.lexists(cold_ready):
        # A consumed cold barrier is never a passive package admission.
        # Subsequent upgrades must present the ordinary source-bound handoff.
        need(os.path.lexists('/var/lib/aegis-install/client/terminal-migrations/'
                            'cold-recovery/phase-05.json') and
             control_present())
    if not control_present():
        return
    # The old installed binary authenticates the sealed predecessor mode.
    # SOCKS carries the original InstallLock only; guarded modes carry both.
    for fd, path in ((9, '/run/aegis-auto-install.lock'),):
        named = os.stat(path, follow_symlinks=False)
        inherited = os.fstat(fd)
        need(stat.S_ISREG(named.st_mode) and named.st_uid == named.st_gid == 0 and
             named.st_nlink == 1 and stat.S_IMODE(named.st_mode) == 0o600 and
             (inherited.st_dev, inherited.st_ino) == (named.st_dev, named.st_ino))
    old = '/usr/local/bin/aegis-client'
    old_fd = held(old)
    os.close(old_fd)
    passive = subprocess.run([old, 'verify-retired-passive-successor',
                              '--lock-fd', '9'], pass_fds=(9,),
                             capture_output=True, timeout=30, check=False)
    need(len(passive.stdout) <= 128 * 1024 and len(passive.stderr) <= 1024)
    if passive.returncode == 0:
        result = passive
        expected_schema = 'aegis_auto_v2_retired_passive_successor_verification_v1'
    else:
        fd, path = 10, '/var/lib/aegis-install/client/device-guard.conf.lock'
        named = os.stat(path, follow_symlinks=False)
        inherited = os.fstat(fd)
        need(stat.S_ISREG(named.st_mode) and named.st_uid == named.st_gid == 0 and
             named.st_nlink == 1 and stat.S_IMODE(named.st_mode) == 0o600 and
             (inherited.st_dev, inherited.st_ino) == (named.st_dev, named.st_ino))
        result = subprocess.run([old, 'verify-retired-successor', '--lock-fd', '9',
                                 '--guard-fd', '10'], pass_fds=(9, 10),
                                capture_output=True, timeout=30, check=False)
        expected_schema = 'aegis_auto_v2_retired_successor_verification_v1'
    need(result.returncode == 0 and 0 < len(result.stdout) <= 128 * 1024 and
         len(result.stderr) <= 1024)
    report = json.loads(result.stdout, object_pairs_hook=lambda pairs:
                        dict(pairs) if len(dict(pairs)) == len(pairs) else need(False))
    need(type(report) is dict and set(report) == {'schema', 'stopped', 'successor', 'retired'} and
         report['schema'] == expected_schema and
         (report['stopped']['stage']['mode'] == 'socks-only') ==
         (expected_schema == 'aegis_auto_v2_retired_passive_successor_verification_v1'))
    next = report['successor']
    need(type(next) is dict and set(next) == {
        'kind', 'intent_sha256', 'old_active_sha256', 'old_stopped_sha256',
        'next_public_payload_root', 'next_candidate_binary',
        'next_candidate_sha256', 'next_installer_sha256',
        'next_bundle_manifest_sha256', 'next_sums_sha256',
        'prior_successor_intent_sha256'} and next['kind'] == 'upgrade' and
         (next['prior_successor_intent_sha256'] is None or
          (type(next['prior_successor_intent_sha256']) is str and
           re.fullmatch('[0-9a-f]{64}', next['prior_successor_intent_sha256']))))
    retired = report['retired']
    guarded = expected_schema == 'aegis_auto_v2_retired_successor_verification_v1'
    need(type(retired) is dict and set(retired) == (
        {'schema', 'boot_id', 'intent_sha256', 'denied_sha256',
         'stopped_successor_sha256', 'retired_sha256', 'deny_policy_sha256',
         'no_live_actors'} if guarded else
        {'schema', 'boot_id', 'intent_sha256', 'stopped_successor_sha256',
         'source_sha256', 'no_live_actors', 'non_actor_units_stopped'}) and
         retired['schema'] == ('aegis_auto_guard_rotation_retired_readback_v1' if guarded else
                               'aegis_auto_v2_passive_successor_retired_v1') and
         retired['no_live_actors'] is True and
         (guarded or retired['non_actor_units_stopped'] is True) and
         retired['boot_id'] == report['stopped']['terminal']['boot_id'])
    root = next['next_public_payload_root']
    need(type(root) is str and re.fullmatch(
        r'/var/lib/aegis-auto/releases/[a-zA-Z0-9-]{16,128}', root) and
         next['next_candidate_binary'] == root + '/bin/aegis-client' and
         next['next_candidate_sha256'] == EXPECTED['files']['usr/local/bin/aegis-client']['sha256'] and
         next['next_installer_sha256'] == EXPECTED['install_sha256'] and
         type(next['next_bundle_manifest_sha256']) is str and
         re.fullmatch(r'[0-9a-f]{64}', next['next_bundle_manifest_sha256']) and
         type(next['next_sums_sha256']) is str and
         re.fullmatch(r'[0-9a-f]{64}', next['next_sums_sha256']))
    need(anchored_digest(root + '/bundle.manifest.json') ==
         next['next_bundle_manifest_sha256'] and
         anchored_digest(root + '/SHA256SUMS') == next['next_sums_sha256'])
    # The AUTO units were conffiles in the prior package. The controlled
    # upgrade changes them to source-owned package files. Admit that change
    # only if every installed old unit still equals the authenticated old
    # generation's retained source, rather than overwriting an operator edit.
    old_input = report['stopped'].get('input')
    need(type(old_input) is dict)
    old_root = old_input.get('public_payload_root')
    need(type(old_root) is str and re.fullmatch(
        r'/var/lib/aegis-auto/releases/[a-zA-Z0-9-]{16,128}', old_root))
    for relative in EXPECTED['files']:
        if not relative.startswith('etc/systemd/system/aegis-auto-'):
            continue
        name = relative.removeprefix('etc/systemd/system/')
        prior = held(old_root + '/packaging/systemd/' + name, 0o444)
        installed = held('/' + relative, 0o644)
        try:
            need(digest(prior) == digest(installed))
        finally:
            os.close(prior)
            os.close(installed)
    # Retention normalizes source mode; package helpers may ship as 0500.
    incoming_source(root)
    if not guarded:
        # This write is made only by the old package preinst after the old
        # binary has authenticated the retired passive actors and source.
        payload = {'schema': 'aegis_auto_v2_passive_package_preinst_v1',
                   'successor_intent_sha256': next['intent_sha256'],
                   'retired_intent_sha256': retired['intent_sha256'],
                   'candidate_sha256': next['next_candidate_sha256'],
                   'old_install_sha256': None}
        install = '/var/lib/aegis-install/client/auto-guardian-install.json'
        old_fd = held(install, 0o600)
        try:
            payload['old_install_sha256'] = digest(old_fd)
        finally:
            os.close(old_fd)
        raw = (json.dumps(payload, sort_keys=True, separators=(',', ':')) + '\n').encode()
        path = '/var/lib/aegis-auto/control/passive-package-preinst.json'
        try:
            out = held(path, 0o600)
        except FileNotFoundError:
            out = None
        if out is not None:
            try:
                need(os.read(out, 4096) == raw)
            finally:
                os.close(out)
        else:
            parent = os.open('/var/lib/aegis-auto/control', os.O_RDONLY |
                             os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
            temporary = '.passive-tmp-' + secrets.token_hex(12)
            out = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                          os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=parent)
            try:
                written = 0
                while written < len(raw):
                    count = os.write(out, raw[written:])
                    need(count > 0)
                    written += count
                os.fsync(out)
            finally:
                os.close(out)
            try:
                libc = ctypes.CDLL(None, use_errno=True)
                rename = libc.renameat2
                rename.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int,
                                   ctypes.c_char_p, ctypes.c_uint)
                rename.restype = ctypes.c_int
                need(rename(parent, temporary.encode(), parent,
                            b'passive-package-preinst.json', 1) == 0)
                os.fsync(parent)
            finally:
                os.close(parent)

try:
    main()
except Exception:
    print('AEGIS client package pre-unpack custody refused', file=sys.stderr)
    sys.exit(1)
PY
  chmod 0755 "$path"
}

write_postinst() {
  local path="$1"
  local package_name="$2"
  cat > "${path}" <<'EOF'
#!/bin/sh
set -e
EOF

  if [[ "${package_name}" == "aegis-server" ]]; then
    cat >> "${path}" <<'EOF'
command -v systemd-sysusers >/dev/null 2>&1
command -v systemd-tmpfiles >/dev/null 2>&1
systemd-sysusers /usr/lib/sysusers.d/aegis-server.conf
systemd-tmpfiles --create /usr/lib/tmpfiles.d/aegis-server.conf
EOF
  else
    cat >> "${path}" <<'EOF'
if [ -e /var/lib/aegis-auto/fresh-passive-abort-current.json ] || [ -L /var/lib/aegis-auto/fresh-passive-abort-current.json ]; then
  echo 'AEGIS fresh passive abort is incomplete; package configuration refused' >&2
  exit 1
fi
if [ -e /var/lib/aegis-auto/control/v2-enabled ] || [ -L /var/lib/aegis-auto/control/v2-enabled ]; then
  # This is the installed source that preinst admitted before unpack.  Never
  # self-heal a sealed AUTO config or normalize an administrator unit here.
  /usr/bin/python3 -I -B - <<'PY_AUTO_PACKAGE_READBACK'
import hashlib,json,os,stat,sys
expected=json.loads(AEGIS_INCOMING_ROSTER_JSON)['files']
try:
    for relative, record in expected.items():
        path='/' + relative
        fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
        try:
            info=os.fstat(fd)
            assert (stat.S_ISREG(info.st_mode) and info.st_uid==info.st_gid==0 and
                    info.st_nlink==1 and info.st_size<=512*1024*1024 and
                    stat.S_IMODE(info.st_mode)==record['mode'])
            value=hashlib.sha256()
            while chunk:=os.read(fd,65536): value.update(chunk)
            assert value.hexdigest()==record['sha256']
        finally:
            os.close(fd)
except Exception:
    print('AEGIS client package installed custody refused',file=sys.stderr)
    sys.exit(1)
PY_AUTO_PACKAGE_READBACK
else
  command -v systemd-tmpfiles >/dev/null 2>&1
  systemd-tmpfiles --create /usr/lib/tmpfiles.d/aegis-client.conf
# Phase 5.0.B: backwards-compat self-heal for the canonical config name.
# `aegis-client.service` reads `/etc/aegis/client/aegis.toml`. Server-
# rendered client bundles ship `aegis-client.toml`. When a user installs
# this .deb and drops the bundle file in directly (without running the
# install.sh `client --bundle ...` rename), make sure the canonical
# path resolves to the bundle file so the service does not restart-
# loop with "config not found".
CLIENT_CONFIG_DIR="/etc/aegis/client"
if [ -d "${CLIENT_CONFIG_DIR}" ] \
   && [ ! -e "${CLIENT_CONFIG_DIR}/aegis.toml" ] \
   && [ ! -L "${CLIENT_CONFIG_DIR}/aegis.toml" ] \
   && [ -f "${CLIENT_CONFIG_DIR}/aegis-client.toml" ]; then
  ln -s aegis-client.toml "${CLIENT_CONFIG_DIR}/aegis.toml"
fi
fi
EOF
  fi

  cat >> "${path}" <<'EOF'
# A chroot with a bind-mounted /run must not reconfigure host units.
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
  # Reapplying a package must preserve administrator enablement choices.
  if [ "${1:-}" = configure ] && [ -z "${2:-}" ]; then
EOF

  if [[ "${package_name}" == "aegis-server" ]]; then
    cat >> "${path}" <<'EOF'
    systemctl preset aegis-server.service
EOF
  else
    cat >> "${path}" <<'EOF'
    systemctl preset aegis-client.service
EOF
  fi

  cat >> "${path}" <<'EOF'
  fi
fi

exit 0
EOF
  chmod 0755 "${path}"
}

write_prerm() {
  local path="$1"
  local package_name="$2"
  if [[ "$package_name" == aegis-client ]]; then
    write_client_removal_hook "$path" prerm
    return
  fi
  cat > "${path}" <<'EOF'
#!/bin/sh
set -e

EOF

  cat >> "${path}" <<'EOF'

case "${1:-}" in
  remove|deconfigure)
    if command -v systemctl >/dev/null 2>&1; then
EOF

  if [[ "${package_name}" == "aegis-server" ]]; then
    cat >> "${path}" <<'EOF'
      systemctl --no-reload disable --now aegis-server.service >/dev/null 2>&1 || true
EOF
  else
    cat >> "${path}" <<'EOF'
      systemctl --no-reload disable --now aegis-client.service >/dev/null 2>&1 || true
EOF
  fi

  cat >> "${path}" <<'EOF'
    fi
    ;;
esac

exit 0
EOF
  chmod 0755 "${path}"
}

write_postrm() {
  local path="$1"
  local package_name="$2"
  if [[ "$package_name" == aegis-client ]]; then
    write_client_removal_hook "$path" postrm
    return
  fi
  cat > "${path}" <<'EOF'
#!/bin/sh
set -e

case "${1:-}" in
  purge)
EOF

  if [[ "${package_name}" == "aegis-server" ]]; then
    cat >> "${path}" <<'EOF'
    if command -v systemd-tmpfiles >/dev/null 2>&1; then
      systemd-tmpfiles --remove /usr/lib/tmpfiles.d/aegis-server.conf >/dev/null 2>&1 || true
    fi
EOF
  else
    cat >> "${path}" <<'EOF'
    if command -v systemd-tmpfiles >/dev/null 2>&1; then
      systemd-tmpfiles --remove /usr/lib/tmpfiles.d/aegis-client.conf >/dev/null 2>&1 || true
    fi
EOF
  fi

  cat >> "${path}" <<'EOF'
    ;;
esac

if command -v systemctl >/dev/null 2>&1; then
  systemctl daemon-reload >/dev/null 2>&1 || true
fi

exit 0
EOF
  chmod 0755 "${path}"
}

write_md5sums() {
  local stage_dir="$1"
  local debian_dir="$2"
  cargo run --locked -q -p aegis-measure -- write-deb-md5-sums \
    --stage-dir "${stage_dir}" \
    --debian-dir "${debian_dir}"
}

build_package() {
  local package_name="$1"
  local package_title="$2"
  local stage_dir="${TMP_DIR}/${package_name}-stage"
  local debian_dir="${stage_dir}/DEBIAN"
  shift 2

  rm -rf "${stage_dir}"
  mkdir -p "${debian_dir}"

  while [[ $# -gt 0 ]]; do
    case "$1" in
      usr/share/doc/aegis/LICENSE-MIT|usr/share/doc/aegis/LICENSE-APACHE|usr/share/doc/aegis/NOTICE|usr/share/doc/aegis/THIRD-PARTY-NOTICES)
        copy_rootfs_file "$1" "${stage_dir}" "usr/share/doc/${package_name}/${1##*/}"
        ;;
      usr/share/doc/aegis/third-party/h2/LICENSE|usr/share/doc/aegis/third-party/tungstenite/LICENSE-MIT|usr/share/doc/aegis/third-party/tungstenite/LICENSE-APACHE)
        copy_rootfs_file "$1" "${stage_dir}" "usr/share/doc/${package_name}/${1#usr/share/doc/aegis/}"
        ;;
      *) copy_rootfs_file "$1" "${stage_dir}" ;;
    esac
    shift
  done

  write_control "${debian_dir}/control" "${package_name}" "${package_title}"
  if [[ "${package_name}" == "aegis-client" ]]; then
    write_client_preinst "${debian_dir}/preinst"
  fi
  write_postinst "${debian_dir}/postinst" "${package_name}"
  write_prerm "${debian_dir}/prerm" "${package_name}"
  write_postrm "${debian_dir}/postrm" "${package_name}"
  if [[ "${package_name}" == "aegis-client" ]]; then
    write_client_upgrade_roster "${stage_dir}" "${debian_dir}"
  fi

  if [[ "${package_name}" == "aegis-server" ]]; then
    cat > "${debian_dir}/conffiles" <<'EOF'
/etc/default/aegis-server
EOF
  else
    cat > "${debian_dir}/conffiles" <<'EOF'
/etc/default/aegis-client
EOF
  fi

  write_md5sums "${stage_dir}" "${debian_dir}"

  local deb_name="${package_name}_${VERSION}_${DEB_ARCH}.deb"
  local unverified_deb="${UNVERIFIED_DIR}/${deb_name}"
  dpkg-deb --root-owner-group --build -Zxz "${stage_dir}" "${unverified_deb}" >/dev/null
  python3 -I -B "${ROOT}/scripts/verify-deb-archive-ownership.py" "${unverified_deb}" >/dev/null

  cargo run --locked -q -p aegis-measure -- write-archive-sha256 \
    --archive "${unverified_deb}" \
    --sha256-path "${unverified_deb}.sha256"
}

build_package \
  "aegis-server" \
  "AEGIS relay server" \
  "usr/local/bin/aegis-server" \
  "usr/lib/systemd/system/aegis-server.service" \
  "usr/lib/sysusers.d/aegis-server.conf" \
  "usr/lib/tmpfiles.d/aegis-server.conf" \
  "etc/default/aegis-server" \
  "usr/share/aegis/examples/aegis-server.toml.example" \
  "${SERVER_HELPER_PATHS[@]}" \
  "usr/lib/systemd/system-preset/90-aegis-server.preset" \
  "usr/share/doc/aegis/README.server.Debian" \
  "usr/share/doc/aegis/README.md" \
  "${PROJECT_LICENSE_PATHS[@]}" \
  "${H2_LICENSE_PATH}" \
  "${TUNGSTENITE_LICENSE_PATHS[@]}"

build_package \
  "aegis-client" \
  "AEGIS Linux-first client runtime" \
  "usr/local/bin/aegis-client" \
  "usr/lib/systemd/system/aegis-client.service" \
  "usr/lib/tmpfiles.d/aegis-client.conf" \
  "usr/lib/systemd/system-preset/90-aegis-client.preset" \
  "usr/share/doc/aegis/README.client.Debian" \
  "etc/default/aegis-client" \
  "usr/share/aegis/examples/config.example.toml" \
  "${CLIENT_PROTECTED_HELPER_PATHS[@]}" \
  "${CLIENT_AUTO_UNIT_PATHS[@]}" \
  "${PROJECT_LICENSE_PATHS[@]}" \
  "${H2_LICENSE_PATH}" \
  "${TUNGSTENITE_LICENSE_PATHS[@]}"

cargo run --locked -q -p aegis-measure -- build-split-deb-manifest \
  --output-dir "${UNVERIFIED_DIR}" \
  --version "${VERSION}" \
  --deb-arch "${DEB_ARCH}"
python3 -I -B "${ROOT}/scripts/verify-split-deb-package-set.py" \
  "${UNVERIFIED_DIR}" --arch "${DEB_ARCH}" --version "${VERSION}" >/dev/null

# A reused output directory must not retain a different same-arch version that
# could be selected by a downstream glob after the new marker appears.
shopt -s nullglob
for existing in "${OUTPUT_DIR}"/aegis-*"_${DEB_ARCH}.deb" \
                "${OUTPUT_DIR}"/aegis-*"_${DEB_ARCH}.deb.sha256"; do
  existing_name="$(basename "${existing}")"
  case "${existing_name}" in
    "aegis-server_${VERSION}_${DEB_ARCH}.deb"|"aegis-client_${VERSION}_${DEB_ARCH}.deb"|\
    "aegis-server_${VERSION}_${DEB_ARCH}.deb.sha256"|"aegis-client_${VERSION}_${DEB_ARCH}.deb.sha256") ;;
    *) echo "stale same-arch split DEB output: ${existing}" >&2; exit 1 ;;
  esac
done
shopt -u nullglob

# Keep the previous complete set until both packages and metadata pass. The
# manifest is removed first and restored last as the publication marker.
rm -f "${OUTPUT_DIR}/split-deb-packages.manifest.json"
for name in "aegis-server_${VERSION}_${DEB_ARCH}.deb" "aegis-client_${VERSION}_${DEB_ARCH}.deb"; do
  mv "${UNVERIFIED_DIR}/${name}" "${OUTPUT_DIR}/${name}"
  mv "${UNVERIFIED_DIR}/${name}.sha256" "${OUTPUT_DIR}/${name}.sha256"
done
mv "${UNVERIFIED_DIR}/split-deb-packages.manifest.json" "${OUTPUT_DIR}/split-deb-packages.manifest.json"

cat <<EOF
Split Debian packages created
-----------------------------
Server package:
  ${OUTPUT_DIR}/aegis-server_${VERSION}_${DEB_ARCH}.deb

Client package:
  ${OUTPUT_DIR}/aegis-client_${VERSION}_${DEB_ARCH}.deb

Manifest:
  ${OUTPUT_DIR}/split-deb-packages.manifest.json
EOF
