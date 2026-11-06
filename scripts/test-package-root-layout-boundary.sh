#!/usr/bin/env bash
# Actual package-root orchestration + manifest writer, inert compiler/binaries.
# This checks staging and refusal gates, not ELF ABI or Linux service behavior.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
MEASURE="${AEGIS_TEST_MEASURE_BINARY:-${ROOT}/target/debug/aegis-measure}"
[[ -x "$MEASURE" ]] || { echo 'Build aegis-measure first.' >&2; exit 1; }
if [[ -n "${AEGIS_PACKAGE_TEST_EVIDENCE_DIR:-}" ]]; then
  [[ "$AEGIS_PACKAGE_TEST_EVIDENCE_DIR" == /* ]] || { echo 'Evidence directory must be absolute.' >&2; exit 1; }
  # mkdir refuses an existing attempt rather than overwriting its evidence.
  mkdir -m 0700 "$AEGIS_PACKAGE_TEST_EVIDENCE_DIR"
  FIXTURE="$AEGIS_PACKAGE_TEST_EVIDENCE_DIR"
else
  FIXTURE="$(mktemp -d)"
fi
finish() {
  local result=$?
  if [[ "$result" != 0 ]]; then
    # CI must retain the concrete failure even when the temporary fixture goes.
    local log
    for log in "$FIXTURE"/*.log; do
      [[ -f "$log" ]] || continue
      echo "Package contract diagnostic: ${log##*/}" >&2
      tail -n 30 "$log" >&2
    done
  fi
  if [[ -z "${AEGIS_PACKAGE_TEST_EVIDENCE_DIR:-}" ]]; then rm -rf "$FIXTURE"; fi
  exit "$result"
}
trap finish EXIT
mkdir -p "$FIXTURE/scripts/lib" "$FIXTURE/home/.cargo/bin" "$FIXTURE/target/release"
cp "$ROOT/scripts/build-package-root.sh" "$ROOT/scripts/build-release-bundle.sh" "$FIXTURE/scripts/"
cp "$ROOT/scripts/lib/host-arch.sh" "$ROOT/scripts/lib/release-toolchain.sh" "$FIXTURE/scripts/lib/"
cp "$ROOT/rust-toolchain.toml" "$ROOT/Cargo.lock" "$ROOT/README.md" "$ROOT/config.example.toml" "$ROOT/aegis-server.toml.example" "$ROOT/install.sh" "$ROOT/bootstrap-install.sh" "$FIXTURE/"
cp -R "$ROOT/packaging" "$FIXTURE/packaging"
mkdir -p "$FIXTURE/tools/geneva" "$FIXTURE/docs/operations" "$FIXTURE/aegis-client"
cp "$ROOT/Cargo.toml" "$FIXTURE/Cargo.toml"
cp "$ROOT/aegis-client/Cargo.toml" "$FIXTURE/aegis-client/Cargo.toml"
cp "$ROOT/LICENSE-MIT" "$ROOT/LICENSE-APACHE" "$ROOT/NOTICE" "$ROOT/THIRD-PARTY-NOTICES" "$FIXTURE/"
mkdir -p "$FIXTURE/third_party/h2"
cp "$ROOT/third_party/h2/LICENSE" "$FIXTURE/third_party/h2/LICENSE"
mkdir -p "$FIXTURE/third_party/tungstenite"
cp "$ROOT/third_party/tungstenite/LICENSE-MIT" "$ROOT/third_party/tungstenite/LICENSE-APACHE" "$FIXTURE/third_party/tungstenite/"
mkdir -p "$FIXTURE/docs/research" "$FIXTURE/tools/measure" "$FIXTURE/tools/transport-lab"
while IFS= read -r document || [[ -n "$document" ]]; do
  cp "$ROOT/docs/research/${document}" "$FIXTURE/docs/research/"
done < "$ROOT/packaging/research-operator-guides.txt"
# Unlisted synthetic inputs must never leak through a directory/glob copy.
printf 'synthetic fixture, never private data\n' > "$FIXTURE/docs/research/.unlisted-token"
printf 'synthetic fixture configuration\n' > "$FIXTURE/docs/research/operator-profile.json"
mkdir "$FIXTURE/docs/research/unlisted-source"
printf 'synthetic source fixture\n' > "$FIXTURE/docs/research/unlisted-source/lib.rs"
cp "$ROOT/tools/measure/Cargo.toml" "$FIXTURE/tools/measure/"
cp "$ROOT/tools/transport-lab/Cargo.toml" "$FIXTURE/tools/transport-lab/"
cp "$ROOT/tools/geneva/install-bridge.sh" "$FIXTURE/tools/geneva/"
cp "$ROOT/tools/geneva/install-relay-profile.sh" "$FIXTURE/tools/geneva/"
cp "$ROOT/tools/geneva/uninstall-relay-profile.sh" "$FIXTURE/tools/geneva/"
cp "$ROOT/docs/geneva-live-bridge.md" "$FIXTURE/docs/"
cp "$ROOT/docs/relay-geneva-installed-profile.md" "$FIXTURE/docs/"
cp "$ROOT/docs/operations/https-bridge.md" "$FIXTURE/docs/operations/"
cp "$ROOT/docs/operations/carrier-program.md" "$FIXTURE/docs/operations/"
cp "$ROOT/docs/operations/web-response-carrier.md" "$FIXTURE/docs/operations/"
cp "$ROOT/docs/operations/webrtc-native.md" "$FIXTURE/docs/operations/"
cp "$ROOT/docs/operations/traffic-privacy.md" "$FIXTURE/docs/operations/"
python3 - "$ROOT" "$FIXTURE" <<'PY'
import re, shutil, sys
from pathlib import Path
root, fixture = map(Path, sys.argv[1:])
for script in ['build-package-root.sh', 'build-release-bundle.sh']:
    text = (root / 'scripts' / script).read_text()
    for name in ['HELPER_SCRIPTS', 'WIDE_HELPER_SCRIPTS']:
        block = re.search(r'^' + name + r'=\((.*?)^\)', text, re.M | re.S)
        if block is None:
            continue
        for relative in re.findall(r'"([A-Za-z0-9_./-]+)"', block.group(1)):
            destination = fixture / 'scripts' / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(root / 'scripts' / relative, destination)
PY
# The ABI/compiler are intentionally inert. The real manifest hashes actual
# staged files and this test never runs a packaged executable or system service.
cat > "$FIXTURE/scripts/lib/release-abi.sh" <<'SH'
verify_linux_release_abi() {
  export AEGIS_RELEASE_MAX_GLIBC=fixture-not-an-abi-proof
  export AEGIS_SERVER_REQUIRED_GLIBC=fixture-not-an-abi-proof
  export AEGIS_CLIENT_REQUIRED_GLIBC=fixture-not-an-abi-proof
  export AEGIS_GENEVA_REQUIRED_GLIBC=fixture-not-an-abi-proof
}
SH
cat > "$FIXTURE/home/.cargo/bin/cargo" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
[[ " $* " == *' --locked '* ]] || exit 91
printf '%s\n' "$*" >> "$AEGIS_PACKAGE_TEST_ROOT/calls"
case " $* " in
  *' release-package-metadata '*) printf '%s\n1.2.3\n' "$AEGIS_PACKAGE_TEST_ROOT/target" ;;
  *' metadata --locked '*)
    # Inert dependency graph only; the real public builder still applies its
    # fixed file policy and hashes every operator input and resulting archive.
    python3 "$AEGIS_PACKAGE_TEST_ROOT/research-fixture.py" metadata
    ;;
  *' build --locked --release '*)
    if [[ "${AEGIS_PACKAGE_TEST_DRIFT:-0}" == 1 ]]; then
      printf '# fixture lock drift\n' >> "$AEGIS_PACKAGE_TEST_ROOT/Cargo.lock"
    fi
    printf '#!/bin/sh\nexit 0\n' > "$AEGIS_PACKAGE_TEST_ROOT/target/release/aegis-server"
    if [[ " $* " == *' -p aegis-client '* ]]; then
      [[ " $* " == *" --target ${AEGIS_BUILD_TARGET} "* ]] || exit 95
      mkdir -p "$AEGIS_PACKAGE_TEST_ROOT/target/${AEGIS_BUILD_TARGET}/release"
      printf '#!/bin/sh\nexit 0\n' > "$AEGIS_PACKAGE_TEST_ROOT/target/${AEGIS_BUILD_TARGET}/release/aegis-client"
      if [[ " $* " == *' --message-format=json-render-diagnostics '* ]]; then
        python3 "$AEGIS_PACKAGE_TEST_ROOT/research-fixture.py" client-build-message
      fi
    fi
    if [[ " $* " == *' -p aegis-geneva '* ]]; then
      printf '#!/bin/sh\nexit 0\n' > "$AEGIS_PACKAGE_TEST_ROOT/target/release/aegis-geneva-bridge"
    fi
    if [[ " $* " == *' -p aegis-measure -p aegis-transport-lab '* ]]; then
      python3 "$AEGIS_PACKAGE_TEST_ROOT/research-fixture.py" build
    fi
    ;;
  *' build-package-root-manifest '*|*' build-release-bundle-manifest '*|*' build-private-research-manifest '*|*' write-archive-sha256 '*)
    while [[ "$1" != -- ]]; do shift; done
    shift
    cd "$AEGIS_PACKAGE_TEST_ROOT"
    exec "$AEGIS_PACKAGE_TEST_MEASURE" "$@"
    ;;
  *) echo 'Unexpected fixture Cargo command' >&2; exit 92 ;;
esac
SH
# Synthetic ELF headers exercise the real manifest's role/hash/target admission.
# They are NEVER executed. Only the three fixed build-side producer commands
# are emulated; all manifest, notices, archive and public-slice code stays real.
cat > "$FIXTURE/research-fixture.py" <<'PY_RESEARCH'
import hashlib, json, os, re, sys
from pathlib import Path
root = Path(os.environ['AEGIS_PACKAGE_TEST_ROOT'])
roles = {
    'aegis-measure': ('measure', ['private-control', 'poisson-control', 'poisson-insertion', 'privacy-pcap-export', 'privacy-study-assemble', 'privacy-frontier', 'brain-outcome-replay']),
    'aegis-transport-lab': ('transport-lab', ['dependencies', 'topology', 'awgn', 'poisson-channel', 'privacy-channel', 'bittraps-channel']),
}
mode, *args = sys.argv[1:]
def version(directory):
    return re.search(r'^version = "([^"]+)"$', (root / 'tools' / directory / 'Cargo.toml').read_text(), re.M)[1]
if mode == 'metadata':
    packages = [{'id': 'fixture-client', 'name': 'aegis-client', 'version': '1.2.3', 'license': 'MIT', 'manifest_path': str(root / 'aegis-client/Cargo.toml'), 'source': None}]
    packages += [{'id': name, 'name': name, 'version': version(directory), 'license': 'MIT', 'manifest_path': str(root / 'tools' / directory / 'Cargo.toml'), 'source': None} for name, (directory, _) in roles.items()]
    print(json.dumps({'workspace_root': str(root), 'workspace_members': [p['id'] for p in packages], 'packages': packages, 'resolve': {'nodes': [{'id': p['id'], 'features': ['chrome-like-quic','chrome-like-tls','raw-socket'] if p['name']=='aegis-client' else [], 'deps': []} for p in packages]}}))
elif mode == 'client-build-message':
    # Inert compiler message describing the actual fixture bytes and path only.
    executable = root / 'target' / os.environ['AEGIS_BUILD_TARGET'] / 'release/aegis-client'
    print(json.dumps({'reason':'compiler-artifact','package_id':'fixture-client','manifest_path':str(root/'aegis-client/Cargo.toml'),'target':{'name':'aegis-client','kind':['bin']},'profile':{'test':False},'features':['chrome-like-quic','chrome-like-tls','raw-socket'],'executable':str(executable)}))
    print(json.dumps({'reason':'build-finished','success':True}))
elif mode == 'build':
    target = os.environ['AEGIS_BUILD_TARGET']
    machine = {'x86_64-unknown-linux-gnu': 62, 'aarch64-unknown-linux-gnu': 183}[target]
    for name in ['aegis-measure', 'aegis-research-measure', 'aegis-transport-lab']:
        path = root / 'target/release' / name
        path.unlink(missing_ok=True)
        if os.environ.get('AEGIS_PACKAGE_TEST_RESEARCH_FAULT') == 'missing-lab' and name == 'aegis-transport-lab':
            continue
        if os.environ.get('AEGIS_PACKAGE_TEST_RESEARCH_FAULT') == 'missing-restricted' and name == 'aegis-research-measure':
            continue
        elf = bytearray(64)
        elf[:7] = b'\x7fELF\x02\x01\x01'
        elf[16:18] = (2).to_bytes(2, 'little')
        elf[18:20] = machine.to_bytes(2, 'little')
        elf[20:24] = (1).to_bytes(4, 'little')
        elf[52:54] = (64).to_bytes(2, 'little')
        # Distinct full/restricted bytes prove which inert role was copied.
        path.write_bytes(elf + name.encode('ascii'))
        path.chmod(0o755)
elif mode == 'info':
    name, executable = args
    directory, capabilities = roles[name]
    source = os.environ['AEGIS_BUILD_GIT_SHA']
    if os.environ.get('AEGIS_PACKAGE_TEST_RESEARCH_FAULT') == 'wrong-source':
        source = '0' * 40
    print(json.dumps({'schema': 'aegis_research_tool_build_info_v1', 'tool': name,
        'crate_version': version(directory), 'source_commit': source,
        'cargo_lock_sha256': os.environ['AEGIS_CARGO_LOCK_SHA256'],
        'target_triple': os.environ['AEGIS_BUILD_TARGET'], 'build_features': 'none',
        'rustc_version': 'rustc ' + os.environ['AEGIS_PACKAGE_TEST_RUST_VERSION'] + ' (fixture)',
        'binary_sha256': hashlib.sha256(Path(executable).read_bytes()).hexdigest(),
        'capabilities': capabilities}))
else:
    raise SystemExit('unexpected research fixture command')
PY_RESEARCH
cat > "$FIXTURE/home/.cargo/bin/timeout" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
bound="$1"; executable="$2"; shift 2
case "$executable" in
  "$AEGIS_PACKAGE_TEST_ROOT/target/release/aegis-measure")
    if [[ "$bound" == 10s && $# == 1 && "$1" == research-build-info ]]; then
      exec python3 "$AEGIS_PACKAGE_TEST_ROOT/research-fixture.py" info aegis-measure "$executable"
    fi
    if [[ "$bound" == 30s && $# == 7 && "$1" == research-tool-notices && "$2" == --root && "$3" == "$AEGIS_PACKAGE_TEST_ROOT" && "$4" == --target && "$5" == "$AEGIS_BUILD_TARGET" && "$6" == --output ]]; then
      exec "$AEGIS_PACKAGE_TEST_MEASURE" "$@"
    fi
    ;;
  "$AEGIS_PACKAGE_TEST_ROOT/"*/bin/aegis-measure)
    if [[ "$bound" == 10s && $# == 1 && "$1" == research-build-info ]]; then
      exec python3 "$AEGIS_PACKAGE_TEST_ROOT/research-fixture.py" info aegis-measure "$executable"
    fi
    ;;
  "$AEGIS_PACKAGE_TEST_ROOT/"*/bin/aegis-transport-lab)
    if [[ "$bound" == 10s && $# == 1 && "$1" == --build-info ]]; then
      exec python3 "$AEGIS_PACKAGE_TEST_ROOT/research-fixture.py" info aegis-transport-lab "$executable"
    fi
    ;;
  "$AEGIS_PACKAGE_TEST_ROOT/target/release/aegis-transport-lab")
    if [[ "$bound" == 10s && $# == 1 && "$1" == --build-info ]]; then
      exec python3 "$AEGIS_PACKAGE_TEST_ROOT/research-fixture.py" info aegis-transport-lab "$executable"
    fi
    ;;
esac
echo 'Unexpected fixture producer invocation' >&2; exit 94
SH
cat > "$FIXTURE/home/.cargo/bin/rustc" <<'SH'
#!/usr/bin/env bash
printf 'rustc %s (fixture)\n' "$AEGIS_PACKAGE_TEST_RUST_VERSION"
if [[ "${1:-}" == -vV ]]; then printf 'host: %s\n' "$AEGIS_BUILD_TARGET"; fi
SH
cat > "$FIXTURE/home/.cargo/bin/cmake" <<'SH'
#!/usr/bin/env bash
exit 0
SH
cat > "$FIXTURE/home/.cargo/bin/git" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
if [[ "${1:-}" == -C ]]; then
  [[ "$2" == "$AEGIS_PACKAGE_TEST_ROOT" ]] || exit 93
  shift 2
else
  [[ "$(pwd -P)" == "$AEGIS_PACKAGE_TEST_ROOT" && "$*" == 'rev-parse HEAD' ]] || exit 93
fi
exec "$AEGIS_PACKAGE_TEST_REAL_GIT" -C "$AEGIS_PACKAGE_TEST_REAL_ROOT" "$@"
SH
chmod +x "$FIXTURE/home/.cargo/bin/"*
export AEGIS_PACKAGE_TEST_ROOT="$FIXTURE" AEGIS_PACKAGE_TEST_MEASURE="$MEASURE"
export AEGIS_PACKAGE_TEST_REAL_GIT="$(command -v git)" AEGIS_PACKAGE_TEST_REAL_ROOT="$ROOT"
export AEGIS_PACKAGE_TEST_RUST_VERSION="$(sed -n 's/^channel = "\([0-9][0-9.]*\)"$/\1/p' "$ROOT/rust-toolchain.toml")"
HOME="$FIXTURE/home" bash "$FIXTURE/scripts/build-package-root.sh" "$FIXTURE/pass" > "$FIXTURE/pass.log" 2>&1
[[ ! -e "$FIXTURE/target/release/aegis-client" ]] || {
  echo 'FAIL: fixture synthesized an implicit-target client' >&2
  exit 1
}
python3 - "$FIXTURE/pass" "$ROOT" <<'PY'
import hashlib, json, subprocess, sys
from pathlib import Path
output, root = map(Path, sys.argv[1:])
package, = [p for p in output.iterdir() if p.is_dir()]
manifest = json.loads((package / 'package-root.manifest.json').read_text())
for helper in ['lib/root-state.sh', 'aegis-device-egress-guard.sh']:
    for prefix in ['usr/local/lib/aegis/helpers/', 'usr/share/aegis/scripts/']:
        name = prefix + helper
        assert name in manifest['files']
        file = package / 'rootfs' / name
        assert file.read_bytes() == (root / 'scripts' / helper).read_bytes()
        assert file.stat().st_mode & 0o777 == 0o755
        assert name in (package / 'SHA256SUMS').read_text()
auto_helpers = ('aegis_installer_auto_v2.py',
                'aegis_auto_capture.py', 'aegis_auto_capture_topology.py',
                'aegis_auto_endpoint.py', 'aegis_auto_guard_policy.py', 'aegis_auto_foreign_policy.py', 'aegis_auto_foreign_monitor.py', 'aegis_auto_ufw_pins.json', 'aegis_initrd_policy.py',
                'aegis_auto_guardian.py', 'aegis_auto_guardian_watchdog.py',
                'aegis_auto_launch.py', 'aegis_auto_native_witness.py',
                'aegis_auto_sink.py', 'aegis_auto_trace_rollback.py',
                'aegis_auto_witness_topology.py')
for helper in auto_helpers:
    source = root / 'scripts/lib' / helper
    for prefix, mode in [('usr/local/lib/aegis/helpers/lib/', 0o500),
                         ('usr/share/aegis/scripts/lib/', 0o755)]:
        name = prefix + helper
        file = package / 'rootfs' / name
        assert name in manifest['files'] and file.read_bytes() == source.read_bytes()
        assert file.stat().st_mode & 0o777 == mode
        assert name in (package / 'SHA256SUMS').read_text()
auto_units = ('aegis-auto-capture-topology.service',
              'aegis-auto-guardian-watchdog.service',
              'aegis-auto-guardian.service',
              'aegis-auto-trace-rollback-actor.service',
              'aegis-auto-trace-rollback.service',
              'aegis-auto-trace-rollback.timer',
              'aegis-auto-witness-topology.service',
              'aegis-device-dhcp-refresh.service',
              'aegis-device-dhcp-refresh.timer')
for unit in auto_units:
    name = 'etc/systemd/system/' + unit
    file = package / 'rootfs' / name
    assert name in manifest['files']
    assert file.read_bytes() == (root / 'packaging/systemd' / unit).read_bytes()
    assert file.stat().st_mode & 0o777 == 0o644
    assert name in (package / 'SHA256SUMS').read_text()
expected = subprocess.check_output(['git', '-C', str(root), 'show', '-s', '--format=%cI', 'HEAD'], text=True).strip()
assert manifest['build_timestamp'] == expected
assert manifest['cargo_lock_sha256'] == hashlib.sha256((root / 'Cargo.lock').read_bytes()).hexdigest()
assert list(output.glob('*.tar.gz'))
PY
# Exercise the operator tar builder too: the public slice must have this exact
# reviewed helper in its checked source bundle before it can include it.
HOME="$FIXTURE/home" bash "$FIXTURE/scripts/build-release-bundle.sh" "$FIXTURE/release-pass" > "$FIXTURE/release-pass.log" 2>&1
[[ ! -e "$FIXTURE/target/release/aegis-client" ]] || {
  echo 'FAIL: fixture synthesized an implicit-target client' >&2
  exit 1
}
python3 - "$FIXTURE/release-pass" "$ROOT" <<'PY_RELEASE'
import hashlib, json, re, sys, tarfile
from pathlib import Path
output, root = map(Path, sys.argv[1:])
bundle, = [p for p in output.iterdir() if p.is_dir() and not p.name.startswith('aegis-research-')]
manifest = json.loads((bundle / 'bundle.manifest.json').read_text())
for helper in ['lib/root-state.sh', 'aegis-device-egress-guard.sh', 'aegis-relay-geneva-profile.sh']:
    name = 'scripts/' + helper
    expected = (root / name).read_bytes()
    assert name in manifest['files']
    if helper == 'aegis-relay-geneva-profile.sh':
        assert name in manifest['helper_scripts']
        assert all((bundle / entry).is_file() for entry in manifest['helper_scripts'] if entry == name)
    assert (bundle / name).read_bytes() == expected
    assert (bundle / name).stat().st_mode & 0o777 == 0o755
    assert name in (bundle / 'SHA256SUMS').read_text()
for helper in ('aegis_auto_guardian.py', 'aegis_auto_guardian_watchdog.py',
               'aegis_auto_launch.py', 'aegis_auto_capture.py'):
    name = 'scripts/lib/' + helper
    assert name in manifest['helper_scripts'] and name in manifest['files']
    assert (bundle / name).read_bytes() == (root / name).read_bytes()
for unit in ('aegis-auto-guardian.service', 'aegis-auto-guardian-watchdog.service',
             'aegis-auto-capture-topology.service', 'aegis-auto-trace-rollback.timer',
             'aegis-device-dhcp-refresh.service', 'aegis-device-dhcp-refresh.timer'):
    name = 'packaging/systemd/' + unit
    assert name in manifest['systemd_templates'] and name in manifest['files']
    assert (bundle / name).read_bytes() == (root / name).read_bytes()
archive = output / (bundle.name + '.tar.gz')
with tarfile.open(archive, 'r:gz') as tar:
    member = tar.getmember(bundle.name + '/scripts/aegis-device-egress-guard.sh')
    assert member.isfile() and member.mode == 0o755
    assert tar.extractfile(member).read() == (root / 'scripts/aegis-device-egress-guard.sh').read_bytes()
    for name, mode in [('bin/aegis-geneva-bridge', 0o755), ('tools/geneva/install-bridge.sh', 0o755), ('docs/geneva-live-bridge.md', 0o644), ('docs/operations/https-bridge.md', 0o644), ('docs/operations/carrier-program.md', 0o644), ('docs/operations/web-response-carrier.md', 0o644), ('docs/operations/webrtc-native.md', 0o644), ('docs/operations/traffic-privacy.md', 0o644), ('tools/geneva/install-relay-profile.sh',0o755), ('tools/geneva/uninstall-relay-profile.sh',0o755), ('docs/relay-geneva-installed-profile.md',0o644), ('packaging/systemd/25-relay-geneva-profile.conf',0o644)]:
        file = bundle / name
        digest = hashlib.sha256(file.read_bytes()).hexdigest()
        assert name in manifest['files']
        assert f'{digest}  {name}' in (bundle / 'SHA256SUMS').read_text()
        member = tar.getmember(bundle.name + '/' + name)
        assert member.isfile() and member.mode == mode
        assert tar.extractfile(member).read() == file.read_bytes()
        if not name.startswith('bin/'):
            assert file.read_bytes() == (root / name).read_bytes()
assert manifest['binaries']['aegis-geneva-bridge']['sha256'] == hashlib.sha256((bundle / 'bin/aegis-geneva-bridge').read_bytes()).hexdigest()
assert manifest['binaries']['aegis-geneva-bridge']['features'] == ['live-linux']
assert 'bin/aegis-geneva-bridge' in manifest['contains_prebuilt_binaries']
assert './install.sh geneva-bridge --prefix /absolute/new/prefix' in manifest['install_entrypoints']
assert './install.sh relay-geneva-profile-remove [--resume-token TOKEN]' in manifest['install_entrypoints']
assert manifest['runtime_abi']['binary_required_glibc']['aegis-geneva-bridge'] == 'fixture-not-an-abi-proof'
assert any('aegis-geneva --features live-linux --bin aegis-geneva-bridge' in line for line in (output.parent / 'calls').read_text().splitlines())
# The inert full binary is present, so this distinguishes fixed role selection.
restricted = output.parent / 'target/release/aegis-research-measure'
full = output.parent / 'target/release/aegis-measure'
assert (bundle / 'bin/aegis-measure').read_bytes() == full.read_bytes()
assert manifest['distribution'] == 'private_administrative_operator'
assert not (bundle / 'research').exists()
assert not (bundle / 'bin/aegis-transport-lab').exists()
private_bundle = output / f"aegis-research-{manifest['version']}-linux-{manifest['arch']}"
private_manifest = json.loads((private_bundle / 'research.manifest.json').read_text())
assert private_manifest['distribution'] == 'private_research_only'
assert (private_bundle / 'bin/aegis-measure').read_bytes() == restricted.read_bytes()
assert restricted.read_bytes() != full.read_bytes()
research = private_manifest['research_operators']
private_archive = output / (private_bundle.name + '.tar.gz')
assert research['installed_fullwide_owner'] is False
assert research['scientific_or_field_acceptance'] is False
assert research['automatic_service_activation'] is False
assert {tool['tool'] for tool in research['tools']} == {'aegis-measure', 'aegis-transport-lab'}
with tarfile.open(private_archive, 'r:gz') as tar:
    for tool in research['tools']:
        role = tool['tool']
        binary_name = 'bin/' + role
        info_name = 'research/' + role + '.build-info.json'
        info = json.loads((private_bundle / info_name).read_text())
        digest = hashlib.sha256((private_bundle / binary_name).read_bytes()).hexdigest()
        assert info['binary_sha256'] == private_manifest['files'][binary_name] == digest
        assert info['source_commit'] == manifest['git_sha']
        assert info['cargo_lock_sha256'] == manifest['cargo_lock_sha256']
        assert info['target_triple'] == manifest['target_triple']
        assert info['capabilities'] == tool['capabilities']
        assert binary_name in private_manifest['files']
        for name, mode in [(binary_name, 0o755), (info_name, 0o644)]:
            assert name in private_manifest['files']
            assert f'{hashlib.sha256((private_bundle / name).read_bytes()).hexdigest()}  {name}' in (private_bundle / 'SHA256SUMS').read_text()
            member = tar.getmember(private_bundle.name + '/' + name)
            assert member.isfile() and member.mode == mode
            assert tar.extractfile(member).read() == (private_bundle / name).read_bytes()
    guides = (output.parent / 'packaging/research-operator-guides.txt').read_text().splitlines()
    for name in ['README.md', 'THIRD-PARTY-NOTICES.txt', *guides]:
        relative = 'research/' + name
        member = tar.getmember(private_bundle.name + '/' + relative)
        assert member.isfile() and member.mode == 0o644
        assert tar.extractfile(member).read() == (private_bundle / relative).read_bytes()
        assert relative in private_manifest['files']
        assert research['leaf_sha256'][relative] == hashlib.sha256((private_bundle / relative).read_bytes()).hexdigest()
    # Check real delivered prose against delivered files, not repository paths.
    for name in ['README.md', *guides]:
        for target in re.findall(r'\]\(([^)]+)\)', (private_bundle / 'research' / name).read_text()):
            if '://' in target or target.startswith('#'):
                continue
            target = target.split('#', 1)[0]
            assert '/' not in target and target in guides, (name, target)
            assert (private_bundle / 'research' / target).is_file(), (name, target)
    assert {p.name for p in (private_bundle / 'research').iterdir()} == set(guides) | {
        'README.md', 'THIRD-PARTY-NOTICES.txt', 'aegis-measure.build-info.json',
        'aegis-transport-lab.build-info.json'}
assert 'aegis-measure' in (private_bundle / 'research/THIRD-PARTY-NOTICES.txt').read_text()
assert 'aegis-transport-lab' in (private_bundle / 'research/THIRD-PARTY-NOTICES.txt').read_text()
assert archive.with_name(archive.name + '.sha256').read_text().split()[0] == hashlib.sha256(archive.read_bytes()).hexdigest()
assert private_archive.with_name(private_archive.name + '.sha256').read_text().split()[0] == hashlib.sha256(private_archive.read_bytes()).hexdigest()
PY_RELEASE
OPERATOR_BUNDLE="$(find "$FIXTURE/release-pass" -mindepth 1 -maxdepth 1 -type d ! -name 'aegis-research-*')"
HOME="$FIXTURE/home" PATH="$FIXTURE/home/.cargo/bin:$PATH" "$MEASURE" build-public-client-delivery \
  --root "$FIXTURE" --operator-bundle "$OPERATOR_BUNDLE" --output-dir "$FIXTURE/public-pass" \
  --channel rc --prerelease true > "$FIXTURE/public-pass.log" 2>&1
python3 - "$FIXTURE/public-pass" "$ROOT" <<'PY_PUBLIC'
import hashlib, json, re, sys, tarfile
from pathlib import Path
output, root = map(Path, sys.argv[1:])
bundle, = [p for p in output.iterdir() if p.is_dir()]
manifest = json.loads((bundle / 'bundle.manifest.json').read_text())
assert manifest['schema'] == 'aegis_client_release_bundle_manifest_v3'
source = (root / 'tools/measure/src/public_client_delivery.rs').read_text()
legacy = set(re.findall(r'"([^"]+)"', re.search(r'const PAYLOAD:.*?= &\[(.*?)\];', source, re.S)[1]))
guard = 'scripts/aegis-device-egress-guard.sh'
actual = {str(p.relative_to(bundle)) for p in bundle.rglob('*') if p.is_file()}
assert actual == legacy | {guard, 'client-cargo-inventory.json', 'SHA256SUMS', 'bundle.manifest.json'}
assert (bundle / guard).read_bytes() == (root / guard).read_bytes()
assert (bundle / guard).stat().st_mode & 0o777 == 0o755
archive, = output.glob('*.tar.gz')
with tarfile.open(archive, 'r:gz') as tar:
    assert all(member.isfile() for member in tar)
    assert tar.extractfile(bundle.name + '/' + guard).read() == (root / guard).read_bytes()
outer, = output.glob('client-release.manifest*.json')
assert json.loads(outer.read_text())['artifacts']['bundle']['archive']['sha256'] == hashlib.sha256(archive.read_bytes()).hexdigest()
assert not any(name in actual for name in ['device.key','server.key','Cargo.lock','bin/aegis-server','aegis-server.toml.example','bin/aegis-geneva-bridge','tools/geneva/install-bridge.sh','docs/geneva-live-bridge.md','scripts/aegis-relay-geneva-profile.sh','tools/geneva/install-relay-profile.sh','tools/geneva/uninstall-relay-profile.sh','docs/relay-geneva-installed-profile.md','packaging/systemd/25-relay-geneva-profile.conf'])
assert not any(name.startswith('research/') or name in ['bin/aegis-measure', 'bin/aegis-transport-lab'] for name in actual)
PY_PUBLIC
# A linked guide missing from the build input must stop actual staging before
# the manifest or archive exists. Preserve the failed attempt and then restore
# only the fixture input, so subsequent refusal controls stay independent.
mv "$FIXTURE/docs/research/live-dependency-admission.md" "$FIXTURE/retained-required-guide.md"
if HOME="$FIXTURE/home" bash "$FIXTURE/scripts/build-release-bundle.sh" "$FIXTURE/research-missing-guide" > "$FIXTURE/research-missing-guide.log" 2>&1; then
  echo 'FAIL: missing required research guide accepted' >&2; exit 1
fi
[[ -z "$(find "$FIXTURE/research-missing-guide" \( -name '*.tar.gz' -o -name 'bundle.manifest.json' -o -name 'SHA256SUMS' \) -print 2>/dev/null)" ]]
grep -Fq 'Missing regular private operator guide: live-dependency-admission.md' "$FIXTURE/research-missing-guide.log"
mv "$FIXTURE/retained-required-guide.md" "$FIXTURE/docs/research/live-dependency-admission.md"
# Missing tools and false producer provenance must stop the actual release
# builder before an archive, even after a successful prior staging attempt.
for fault in missing-lab missing-restricted wrong-source; do
  if HOME="$FIXTURE/home" AEGIS_PACKAGE_TEST_RESEARCH_FAULT="$fault" bash "$FIXTURE/scripts/build-release-bundle.sh" "$FIXTURE/research-$fault" > "$FIXTURE/research-$fault.log" 2>&1; then
    echo "FAIL: research producer fault accepted: $fault" >&2; exit 1
  fi
  [[ -z "$(find "$FIXTURE/research-$fault" -name '*.tar.gz' -print 2>/dev/null)" ]]
done
grep -Fq 'aegis-transport-lab' "$FIXTURE/research-missing-lab.log"
grep -Fq 'aegis-research-measure' "$FIXTURE/research-missing-restricted.log"
grep -Fq 'private research operator input refused' "$FIXTURE/research-wrong-source.log"
rm "$FIXTURE/calls"
if HOME="$FIXTURE/home" AEGIS_PACKAGE_TEST_RUST_VERSION=0.0.0 bash "$FIXTURE/scripts/build-package-root.sh" "$FIXTURE/wrong-toolchain" > "$FIXTURE/toolchain.log" 2>&1; then
  echo 'FAIL: wrong toolchain accepted' >&2; exit 1
fi
[[ ! -e "$FIXTURE/calls" ]]
grep -Fq 'release requires the exact rust-toolchain.toml compiler' "$FIXTURE/toolchain.log"
if HOME="$FIXTURE/home" AEGIS_PACKAGE_TEST_DRIFT=1 bash "$FIXTURE/scripts/build-package-root.sh" "$FIXTURE/drift" > "$FIXTURE/drift.log" 2>&1; then
  echo 'FAIL: lock drift accepted' >&2; exit 1
fi
grep -Fq 'Cargo.lock changed during package build' "$FIXTURE/drift.log"
if grep -q 'build-package-root-manifest' "$FIXTURE/calls"; then echo 'FAIL: manifest after lock drift' >&2; exit 1; fi
[[ -z "$(find "$FIXTURE/drift" -name '*.tar.gz' -print 2>/dev/null)" ]]
printf 'PASS: actual package/operator/public-v2 helper and private research-pair layout + archive/checksums + commit timestamp; missing tool/missing restricted producer/false provenance/wrong compiler/lock drift stop before packaging (inert compiler/producers, no ABI/service/license proof)\n'
