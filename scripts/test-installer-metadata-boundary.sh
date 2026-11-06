#!/usr/bin/env bash
# Inert temporary fixtures; no installer/system-service execution.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd -P)"
FIXTURE="$(mktemp -d /private/tmp/aegis-metadata.XXXXXX 2>/dev/null || mktemp -d /tmp/aegis-metadata.XXXXXX)"
FIXTURE="$(cd "${FIXTURE}" && pwd -P)"
trap 'rm -rf -- "${FIXTURE}"' EXIT
eval "$(sed -n '/^install_atomic_write() {$/,/^}$/p' "${ROOT}/install.sh")"

printf 'first\n' | install_atomic_write "${FIXTURE}/metadata/install.json" 0644 strict
printf 'second\n' | install_atomic_write "${FIXTURE}/metadata/install.json" 0600 strict
[[ "$(cat "${FIXTURE}/metadata/install.json")" == second ]]
python3 - "${FIXTURE}/metadata/install.json" <<'PY'
import os, stat, sys
s = os.stat(sys.argv[1])
assert stat.S_IMODE(s.st_mode) == 0o600
assert s.st_uid == os.geteuid()
PY

printf 'untouched\n' > "${FIXTURE}/outside"
ln -s "${FIXTURE}/outside" "${FIXTURE}/metadata/link.json"
if printf 'refused' | install_atomic_write "${FIXTURE}/metadata/link.json" 0644 strict 2>/dev/null; then
  echo 'FAIL: destination link accepted' >&2; exit 1
fi
[[ "$(cat "${FIXTURE}/outside")" == untouched ]]
ln "${FIXTURE}/outside" "${FIXTURE}/metadata/hardlink.json"
if printf 'refused' | install_atomic_write "${FIXTURE}/metadata/hardlink.json" 0644 strict 2>/dev/null; then
  echo 'FAIL: destination hardlink accepted' >&2; exit 1
fi
ln -s "${FIXTURE}/metadata" "${FIXTURE}/parent-link"
if printf 'refused' | install_atomic_write "${FIXTURE}/parent-link/other.json" 0644 strict 2>/dev/null; then
  echo 'FAIL: parent link accepted' >&2; exit 1
fi
[[ ! -e "${FIXTURE}/metadata/other.json" ]]

mkdir "${FIXTURE}/runtime"
chmod 0777 "${FIXTURE}/runtime"
if printf 'refused' | install_atomic_write "${FIXTURE}/runtime/install.json" 0644 strict 2>/dev/null; then
  echo 'FAIL: writable directory accepted for privileged record' >&2; exit 1
fi
# Runtime metadata uses the same atomic writer but explicitly permits the
# service-writable final directory. Existing destinations are never opened.
printf 'runtime\n' | install_atomic_write "${FIXTURE}/runtime/wide-profile.json" 0644
[[ "$(cat "${FIXTURE}/runtime/wide-profile.json")" == runtime ]]
if python3 -c 'print("x" * 1048577)' | install_atomic_write "${FIXTURE}/metadata/install.json" 0644 strict 2>/dev/null; then
  echo 'FAIL: oversized record accepted' >&2; exit 1
fi
[[ "$(cat "${FIXTURE}/metadata/install.json")" == second ]]
[[ -z "$(find "${FIXTURE}" -name '.aegis-install-*' -print)" ]]
printf '%s\n' 'PASS: metadata replacement, permissions, links, trusted directory policy, bounded writes, previous record preservation'

# Load the real writer together with the following definitions under the OS
# /bin/bash (3.2 on macOS). Syntax-only checks cannot catch swallowed functions.
python3 - "${ROOT}" "${FIXTURE}" <<'PY_MANIFEST_CONTRACT'
import hashlib, json, os, re, stat, subprocess, sys
from pathlib import Path
root, work = map(Path, sys.argv[1:])
source = (root / 'install.sh').read_text()
atomic = re.search(r'^install_atomic_write\(\) \{\n.*?^\}', source, re.M | re.S)
assert atomic
start = source.index('\nwrite_install_manifest() {')
end = source.index('\ninstall_copy_file() {', start)
definitions = work / 'manifest-definitions.sh'
definitions.write_text(atomic[0] + '\n' + source[start:end])
package = work / 'package with spaces'
package.mkdir(mode=0o700)
bundle = package / 'bundle.manifest.json'
bundle.write_text(json.dumps({'version': '1.2.3', 'git_sha': '1' * 40,
    'build_timestamp': '2026-09-11T00:00:00Z', 'platform': 'linux', 'arch': 'x86_64'}))
binary = package / 'synthetic-client'
binary.write_text('#!/bin/sh\nprintf "aegis-client fixture 1.2.3\\n"\n')
binary.chmod(0o700)
manifest = work / 'actual-manifest' / 'install.json'
env = {**os.environ, 'ROOT': str(package), 'INSTALL_SOURCE_MANIFEST_URL': 'https://fixture.invalid/release.json',
       'INSTALL_SOURCE_RELEASE_CHANNEL': 'rc'}
script = '''set -euo pipefail
source "$1"
declare -F write_install_manifest >/dev/null
declare -F write_server_config >/dev/null
declare -F install_text_file >/dev/null
write_install_manifest client "$2" "$3"
'''
def write(destination, executable=binary):
    return subprocess.run(['/bin/bash', '-c', script, 'manifest-contract', str(definitions),
                           str(destination), str(executable)], env=env, text=True, capture_output=True, timeout=15)
result = write(manifest)
assert result.returncode == 0, result.stderr
value = json.loads(manifest.read_text())
assert value['schema'] == 'aegis_install_manifest_v1' and value['role'] == 'client'
assert value['version'] == '1.2.3' and value['git_sha'] == '1' * 40
assert value['binary_sha256'] == hashlib.sha256(binary.read_bytes()).hexdigest()
assert value['binary_version'] == 'aegis-client fixture 1.2.3'
assert value['source_manifest_url'] == env['INSTALL_SOURCE_MANIFEST_URL']
assert value['source_release_channel'] == 'rc'
assert value['bundle_manifest_path'] == str(bundle)
assert manifest.stat().st_uid == os.geteuid() and stat.S_IMODE(manifest.stat().st_mode) == 0o644
before, inode = manifest.read_bytes(), manifest.stat().st_ino
valid = bundle.read_bytes()
bundle.write_text('{invalid fixture JSON')
result = write(manifest)
assert result.returncode != 0
assert manifest.read_bytes() == before and manifest.stat().st_ino == inode
bundle.write_bytes(valid)
absent_parent = work / 'must-remain-absent'
result = write(absent_parent / 'install.json', package / 'missing-binary')
assert result.returncode != 0 and not absent_parent.exists(), 'payload failure crossed the filesystem write boundary'
outside = work / 'manifest-outside'
outside.write_text('untouched')
link = work / 'manifest-link'
link.symlink_to(outside)
result = write(link)
assert result.returncode != 0 and outside.read_text() == 'untouched'
print('PASS: /bin/bash loads following definitions; actual manifest/hash/version written; invalid JSON/missing binary preserve state; symlink refused')
PY_MANIFEST_CONTRACT
