#!/usr/bin/env bash
# Exercise production orchestration with temporary plans and no host mutation.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
python3 - "${ROOT}" <<'PY'
import json
import hashlib
import os
import re
import subprocess
import sys
import tempfile
import tarfile
import time
import tomllib
from pathlib import Path

root = Path(sys.argv[1])
installer = (root / 'install.sh').read_text()
bootstrap = (root / 'bootstrap-install.sh').read_text()

def function(source, name):
    match = re.search(r'^' + name + r'\(\) \{\n.*?^\}', source, re.M | re.S)
    assert match, name
    return match[0] + '\n'

env = os.environ | {'AEGIS_INSTALL_VALIDATE_MODE_ONLY': '1'}
for key in ('AEGIS_INSTALL_PROFILE', 'AEGIS_INSTALL_MODE', 'AEGIS_WIDE_UDP_POLICY', 'AEGIS_WIDE_DNS_POLICY', 'AEGIS_WIDE_IPV6_POLICY'):
    env.pop(key, None)
for options, expected in (([], 'auto'), (['--profile', 'auto'], 'auto'),
                           (['--mode', 'auto'], 'auto'), (['--profile', 'socks-only'], 'socks-only'),
                           (['--profile', 'full-wide-tun'], 'full-wide-tun')):
    result = subprocess.run(['bash', str(root / 'install.sh'), 'client', *options], env=env, text=True, capture_output=True)
    assert result.returncode == 0, result.stderr
    assert f'product_mode={expected}\n' in result.stdout
for options in (['--profile', 'auto', '--udp-carry'], ['--profile', 'auto', '--udp-policy', 'native']):
    result = subprocess.run(['bash', str(root / 'install.sh'), 'client', *options], env=env, capture_output=True)
    assert result.returncode != 0

with tempfile.TemporaryDirectory(prefix='aegis-adaptive-contract-') as tmp:
    work = Path(tmp)
    fixture_home = work / 'home'
    fixture_home.mkdir(mode=0o700)
    # Exercise the real floor, restricted to this contract's temporary tree
    # even when CI itself runs as root. No production state path is touched.
    fixture_bootstrap = work / 'bootstrap-install.sh'
    fixture_bootstrap.write_text(bootstrap.replace('/var/lib/aegis-install/releases',
        str(work / 'root-release-floor')).replace('/Library/Application Support/Aegis/Install/releases',
        str(work / 'root-release-floor')))
    fake = work / 'client'
    fake.write_text('#!/bin/bash\ncat "$FIXTURE_PLAN"\nexit "${FIXTURE_EXIT:-0}"\n')
    fake.chmod(0o755)
    plan_path = work / 'plan.json'
    script = work / 'resolver.sh'
    script.write_text('''set -euo pipefail
AUTO_PROFILE=1
AUTO_PLAN_PATH=""
PRODUCT_MODE=auto
OPERATOR_MODE=""
SYSTEMD_DIR=/etc/systemd/system
UDP_CARRY=0
TEMP_PATHS=()
resolve_wide_policies() { printf '%s' "$PRODUCT_MODE" > "$RESOLVED_POLICY"; }
default_client_state_dir() { printf '/var/lib/aegis-client'; }
''' + function(installer, 'install_manifest_path_for_role') + function(installer, 'product_mode_to_operator') + function(installer, 'resolve_auto_profile') + '''
resolve_auto_profile "$FAKE_CLIENT" /unused/config /unused/state
printf '%s:%s:%s' "$PRODUCT_MODE" "$OPERATOR_MODE" "$UDP_CARRY"
''')
    run_env = os.environ | {'FAKE_CLIENT': str(fake), 'FIXTURE_PLAN': str(plan_path),
                           'RESOLVED_POLICY': str(work / 'resolved'), 'TMPDIR': str(work), 'HOME': str(fixture_home)}
    for mode, operator, udp in [('full-wide-tun', 'client-ipv6-tun-smoltcp', 1),
                                 ('wide-redirect-safe', 'client-wide-redirect', 0)]:
        plan_path.write_text(json.dumps({'schema': 'aegis_auto_install_plan_v1', 'status': 'planned',
            'product_mode': mode, 'connectivity_verified': False, 'message': 'fixture plan', 'reasons': []}))
        result = subprocess.run(['bash', str(script)], env=run_env, capture_output=True, text=True)
        assert result.returncode == 0, result.stderr
        assert result.stdout == f'{mode}:{operator}:{udp}', result.stdout
    for value, code in [('{}', 0), ('not json', 0),
                         (json.dumps({'status': 'blocked', 'message': 'missing capability', 'reasons': []}), 1)]:
        (work / 'resolved').unlink(missing_ok=True)
        plan_path.write_text(value)
        result = subprocess.run(['bash', str(script)], env=run_env | {'FIXTURE_EXIT': str(code)}, capture_output=True)
        assert result.returncode != 0
        assert not (work / 'resolved').exists(), 'invalid plan reached policy activation'

    # Package repair is idempotent, includes client signature verification, and
    # leaves explicitly requested per-app installs free of wide prerequisites.
    package_script = work / 'packages.sh'
    package_script.write_text('''set -euo pipefail
ROLE=client
FORWARDED_ARGS=("$@")
has_ca_certificates() { return 0; }
prereq_has_command() { case " $MISSING " in *" $1 "*) return 1 ;; *) return 0 ;; esac; }
''' + function(bootstrap, 'append_unique_word') + function(bootstrap, 'automatic_client_requested') + function(bootstrap, 'bootstrap_prereq_packages') + 'bootstrap_prereq_packages\n')
    missing = 'openssl ip iptables ip6tables curl getent timeout'
    def packages(args, absent):
        result = subprocess.run(['bash', str(package_script), *args], env=run_env | {'MISSING': absent}, text=True, capture_output=True)
        assert result.returncode == 0, result.stderr
        return result.stdout.split()
    assert packages([], '') == []
    assert packages([], missing) == ['openssl', 'iproute2', 'iptables', 'curl', 'libc-bin', 'coreutils']
    assert packages(['--profile', 'socks-only'], missing) == ['openssl']

    # Execute the actual no-bundle config step: upgrades preserve credentials;
    # fresh/manual installs still use the existing example-copy operation.
    config_step = work / 'config-step.sh'
    config_step.write_text('''set -euo pipefail
ROOT=/unused
install_copy_file() { printf 'example config' > "$2"; }
''' + function(installer, 'install_client_config_without_bundle') + 'install_client_config_without_bundle "$CONFIG_PATH"\n')
    config_path = work / 'saved config.toml'
    config_path.write_text('existing relay credentials and policy')
    for automatic, expected in [('1', 'existing relay credentials and policy'), ('0', 'example config')]:
        result = subprocess.run(['bash', str(config_step)], env=run_env | {
            'AUTO_PROFILE': automatic, 'CONFIG_PATH': str(config_path)}, capture_output=True)
        assert result.returncode == 0
        assert config_path.read_text() == expected
    config_path.unlink()
    subprocess.run(['bash', str(config_step)], env=run_env | {
        'AUTO_PROFILE': '1', 'CONFIG_PATH': str(config_path)}, check=True, capture_output=True)
    assert config_path.read_text() == 'example config'

    # A full-profile access bundle must not launch TUN/generic UDP engines when
    # automatic host planning chose limited mode. Preserve relay credentials,
    # make repeated normalization harmless, and leave explicit/full modes alone.
    normalize = work / 'normalize.sh'
    normalize.write_text('set -euo pipefail\n' + ''.join(function(installer, name) for name in (
        'set_client_config_ipv6_tun', 'set_client_config_udp_contract',
        'normalize_auto_limited_config')) + 'normalize_auto_limited_config "$CONFIG_PATH"\n')
    old_bundle = '''[relay]
server = "127.0.0.1:443"
auth_token = "local-fixture-only"
[ingress.wide]
ipv6_tun_carried = true
udp_capture_contract = "generic_capture_unstable"
'''
    for automatic, mode, limited in [('1', 'wide-redirect-safe', True),
                                    ('1', 'full-wide-tun', False),
                                    ('0', 'wide-redirect-safe', False)]:
        config_path.write_text(old_bundle)
        for _ in range(2):
            subprocess.run(['bash', str(normalize)], env=run_env | {
                'AUTO_PROFILE': automatic, 'PRODUCT_MODE': mode,
                'CONFIG_PATH': str(config_path)}, check=True, capture_output=True)
            cfg = tomllib.loads(config_path.read_text())
            assert cfg['relay'] == tomllib.loads(old_bundle)['relay']
            assert cfg['ingress']['wide']['ipv6_tun_carried'] is (not limited)
            assert cfg['ingress']['wide']['udp_capture_contract'] == (
                'preview_allowlist_only' if limited else 'generic_capture_unstable')
    client_install = function(installer, 'install_client_role')
    assert client_install.index('normalize_auto_limited_config "${config_path}"') < client_install.index('activate_systemd_unit "aegis-client.service"')

    # Execute the real bootstrap entry point. Fake package manager + downloader
    # record ordering; no packages, services or network requests are performed.
    bindir = work / 'bin'
    bindir.mkdir()
    events = work / 'events'
    for name, body in {
        'apt-get': 'printf "apt %s\\n" "$*" >> "$EVENTS"\nexit "${APT_RESULT:-0}"\n',
        'sudo': 'exec "$@"\n',
        'curl': 'echo download >> "$EVENTS"\nexit 22\n',
    }.items():
        path = bindir / name
        path.write_text('#!/bin/bash\n' + body)
        path.chmod(0o755)
    boot_env = run_env | {
        'PATH': str(bindir) + os.pathsep + os.environ['PATH'],
        'EVENTS': str(events), 'AEGIS_BOOTSTRAP_HOST_FAMILY_OVERRIDE': 'debian_like',
        'AEGIS_BOOTSTRAP_OS_KIND_OVERRIDE': 'linux',
        'AEGIS_BOOTSTRAP_ARCH_OVERRIDE': 'x86_64',
        'AEGIS_BOOTSTRAP_APT_GET_BIN': str(bindir / 'apt-get'),
        'AEGIS_BOOTSTRAP_SUDO_BIN': str(bindir / 'sudo'),
        'AEGIS_BOOTSTRAP_SIMULATE_MISSING_COMMANDS': 'openssl',
    }
    for apt_result in ('0', '7'):
        events.unlink(missing_ok=True)
        result = subprocess.run(['bash', str(fixture_bootstrap), 'client',
            '--profile', 'socks-only', '--manifest-url', 'https://fixture.invalid/release.manifest.json'],
            env=boot_env | {'APT_RESULT': apt_result}, text=True, capture_output=True)
        assert result.returncode != 0, 'fixture download/package failure unexpectedly succeeded'
        lines = events.read_text().splitlines()
        assert lines[0] == 'apt update', lines
        if apt_result == '0':
            assert lines[1:3] == ['apt install -y openssl', 'download'], lines
        else:
            assert 'download' not in lines, 'download ran after package preparation failed'

    # Complete signed Linux bootstrap against a local tarball whose installer
    # is just a marker writer. This proves OS dispatch + preparation did not
    # break the successful handoff or forward the wrong role/profile.
    (bindir / 'curl').unlink()
    for name in ('ip', 'iptables', 'ip6tables', 'nft', 'flock', 'getent', 'timeout'):
        shim = bindir / name
        shim.write_text('#!/bin/bash\nexit 99\n')
        shim.chmod(0o755)
    payload = work / 'payload'
    payload.mkdir()
    # This outer manifest has no public-client distribution. Exercise the
    # signed private source-layout exception for missing inner provenance;
    # an install.sh-only archive must continue to fail closed.
    (payload / 'Cargo.toml').write_text('INERT_SOURCE_LAYOUT_MARKER\n')
    (payload / 'aegis-client').mkdir()
    (payload / 'aegis-server').mkdir()
    marker = work / 'handoff'
    inner = payload / 'install.sh'
    inner.write_text('#!/bin/bash\nprintf "%s\\n" "$@" > "$HANDOFF"\n')
    inner.chmod(0o755)
    archive = work / 'release.tar.gz'
    with tarfile.open(archive, 'w:gz') as tar:
        tar.add(payload, arcname='aegis-fixture')
    manifest = work / 'fixture.json'
    manifest.write_text(json.dumps({'schema': 'aegis_linux_release_manifest_v1',
        'platform': 'linux', 'arch': 'x86_64', 'target_triple': 'x86_64-unknown-linux-gnu',
        'version': '0.0.0', 'channel': 'rc', 'prerelease': True,
        'release_policy': {'schema': 'aegis_release_policy_v1',
            'authority': 'github:fixture/aegis:.github/workflows/release.yml', 'sequence': 1,
            'tag': 'v0.0.0-rc.1', 'issued_at_unix': int(time.time()) - 10,
            'expires_at_unix': int(time.time()) + 3600},
        'artifacts': {'bundle': {'archive': {
            'path': archive.name, 'sha256': hashlib.sha256(archive.read_bytes()).hexdigest()}}}}))
    key, pub = work / 'key.pem', work / 'pub.pem'
    for args in (['genpkey', '-algorithm', 'ed25519', '-out', str(key)],
                 ['pkey', '-in', str(key), '-pubout', '-out', str(pub)],
                 ['pkeyutl', '-sign', '-inkey', str(key), '-rawin', '-in', str(manifest), '-out', str(manifest) + '.sig']):
        subprocess.run(['openssl', *args], check=True, capture_output=True)
    result = subprocess.run(['bash', str(fixture_bootstrap), 'client', '--manifest-url', manifest.as_uri(),
        '--release-authority', 'github:fixture/aegis:.github/workflows/release.yml', '--minimum-release-sequence', '1',
        '--bundle', '/fixture/access bundle'], env=boot_env | {
            'AEGIS_BOOTSTRAP_HOST_FAMILY_OVERRIDE': 'generic_linux',
            'AEGIS_BOOTSTRAP_SIMULATE_MISSING_COMMANDS': '',
            'AEGIS_INSTALL_MANIFEST_PUBKEY': str(pub), 'HANDOFF': str(marker),
        }, text=True, capture_output=True)
    assert result.returncode == 0, result.stderr
    assert marker.read_text().splitlines() == ['client', '--bundle', '/fixture/access bundle']
    floor = (work / 'root-release-floor' if os.geteuid() == 0 else
             fixture_home / '.local/state/aegis-install/releases')
    record = json.loads((floor / 'client-linux-x86_64.json').read_text())
    assert record['sequence'] == 1 and record['manifest_sha256'] == hashlib.sha256(manifest.read_bytes()).hexdigest()
    assert not list(floor.glob('*.pending.json')), 'successful handoff left an unresolved release journal'

print('PASS: adaptive installer defaults, explicit profiles, planner failures, UDP activation, and dependency repair')
PY
