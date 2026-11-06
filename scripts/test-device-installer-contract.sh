#!/usr/bin/env bash
# Local synthetic material only. Production installer functions are extracted
# into a temp fixture; all service/config/network mutation entry points are inert.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd -P)"
CLIENT="${AEGIS_DEVICE_CLIENT:-${ROOT}/target/debug/aegis-client}"
SERVER="${AEGIS_DEVICE_SERVER:-${ROOT}/target/debug/aegis-server}"
python3 - "${ROOT}" "${CLIENT}" "${SERVER}" <<'PY'
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys
import tempfile

root, client, server = Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3])
source = (root / 'install.sh').read_text()

def run(command, ok=True, **kwargs):
    result = subprocess.run([str(part) for part in command], capture_output=True, text=True, **kwargs)
    assert (result.returncode == 0) == ok, (command, result.returncode, result.stdout, result.stderr)
    return result

def function(name):
    match = re.search(r'^' + name + r'\(\) \{\n.*?^\}', source, re.M | re.S)
    assert match, name
    return match[0] + '\n'

prepare = function('prepare_device_bundle')
assert '[[ ${EUID} -eq 0 ]]' in prepare
# This fixture changes exactly the administrative-UID check to its own UID;
# every referenced destination is a child of the temp tree. Product root gate stays.
prepare = prepare.replace('[[ ${EUID} -eq 0 ]]', '[[ "$(id -u)" == "$FIXTURE_UID" ]]')
managed_identity_gate = '"$identity" != /var/lib/aegis-identity/client'
assert prepare.count(managed_identity_gate) == 1
unrebased_prepare = prepare
# Only the extracted fixture translates this one managed-path comparison.
# The unmodified product comparison is exercised separately below.
prepare = prepare.replace(managed_identity_gate,
    '"$identity" != "${FIXTURE_AUTO_MANAGED_IDENTITY:-/var/lib/aegis-identity/client}"')
role = function('install_client_role')
assert role.index('prepare_device_bundle ') < role.index('prepare_client_config_boundary ')
assert role.index('prepare_device_bundle ') < role.index('apply_existing_install_choice ' + '"client" "${existing_install_choice}" "${BUNDLE_PATH:-}"')
run([client, 'device', 'bundle-create', '--help'])
run([server, 'device', '--help'])
path_gate = function('device_service_identity_path')
for path in ['/root/device', '/home/user/device', '/run/user/1000/device', '/tmp/device',
             '/var/tmp/device', '/dev/shm/device', '/proc/device', '/sys/device']:
    run(['bash', '-c', path_gate + '\ndevice_service_identity_path "$1"', 'fixture', path], ok=False)
run(['bash', '-c', path_gate + '\ndevice_service_identity_path "$1"', 'fixture', '/var/lib/aegis-identity/client'])

with tempfile.TemporaryDirectory(prefix='aegis-device-installer-') as raw:
    work = Path(raw).resolve()
    ca = work / 'issuer.pem'
    ca_key = work / 'issuer.key'
    run(['openssl', 'req', '-new', '-x509', '-newkey', 'ed25519', '-nodes',
         '-keyout', ca_key, '-out', ca, '-days', '3', '-subj', '/CN=Synthetic Test CA',
         '-addext', 'basicConstraints=critical,CA:TRUE', '-addext', 'keyUsage=critical,keyCertSign,cRLSign'])
    ca_key.chmod(0o600)
    profile = work / 'profile.json'
    profile.write_text(json.dumps({'schema': 'aegis_device_bundle_v1', 'relay_server': 'relay.test:443',
        'outer_server_name': 'relay.test', 'inner_server_name': 'origin.test', 'udp': False}))
    bundle = work / 'public-bundle'
    create = [client, 'device', 'bundle-create', '--bundle-dir', bundle, '--profile', profile,
              '--outer-ca', ca, '--inner-ca', ca, '--device-ca', ca]
    run(create)
    assert set(p.name for p in bundle.iterdir()) == {'bundle.json', 'outer-ca.pem', 'inner-ca.pem', 'device-ca.pem'}
    assert not any('PRIVATE KEY' in p.read_text() for p in bundle.iterdir())
    bad_create = create.copy()
    bad_create[bad_create.index('--bundle-dir') + 1] = work / 'must-not-exist'
    bad_create[bad_create.index('--inner-ca') + 1] = ca_key
    run(bad_create, ok=False)
    assert not (work / 'must-not-exist').exists()

    identity = work / 'identity'
    config = work / 'config'
    state = work / 'runtime'
    config.mkdir()
    previous = config / 'aegis.toml'
    previous.write_text('existing working config must not change during preparation')
    marker = work / 'mutation'
    diagnostic_client = work / 'synthetic-client'
    diagnostic_client.write_text('#!/bin/sh\nexec ' + shlex.quote(str(client)) + ' --diagnostic-logs "$@"\n')
    diagnostic_client.chmod(0o700)
    runner = work / 'fixture.sh'
    runner.write_text('''set -euo pipefail
ROOT="$FIXTURE_ROOT"
PREFIX="$FIXTURE_ROOT/prefix"
CONFIG_DIR="${FIXTURE_CONFIG_DIR:-$FIXTURE_ROOT/config}"
STATE_DIR="${FIXTURE_STATE_DIR:-$FIXTURE_ROOT/runtime}"
LOG_DIR="${FIXTURE_LOG_DIR:-$FIXTURE_ROOT/log}"
SYSTEMD_DIR="$FIXTURE_ROOT/systemd"
ENV_DIR="$FIXTURE_ROOT/env"
BUNDLE_PATH="${FIXTURE_BUNDLE:-$FIXTURE_ROOT/public-bundle}"
BUNDLE_URL=""
BUNDLE_URL_FILE=""
CLIENT_PACKAGE=""
STAGE_AUTO_DEVICE_GUARD=0
SOURCE_LAYOUT=0
DEVICE_BUNDLE=0
DEVICE_PUBLIC_BUNDLE=""
DEVICE_PRODUCT_MODE=""
DEVICE_ID="${FIXTURE_DEVICE_ID:-fixture-device}"
DEVICE_CERTIFICATE="${FIXTURE_CERTIFICATE:-}"
DEVICE_IDENTITY_DIR="${FIXTURE_IDENTITY:-$FIXTURE_ROOT/identity}"
BUNDLE_INSECURE=0
PRODUCT_MODE="${FIXTURE_PRODUCT_MODE:-socks-only}"
OPERATOR_MODE="${FIXTURE_OPERATOR_MODE:-}"
MASQUE_SERVER="${FIXTURE_MASQUE_SERVER:-}" MASQUE_CA="${FIXTURE_MASQUE_CA:-}" GENEVA_STRATEGY_FILE="${FIXTURE_GENEVA_STRATEGY_FILE:-}" OPERATOR_TRANSPORT="${FIXTURE_OPERATOR_TRANSPORT:-}" FRONTED_AUTHORITY="${FIXTURE_FRONTED_AUTHORITY:-}"
WIDE_UDP_POLICY="${FIXTURE_WIDE_UDP_POLICY:-}" WIDE_DNS_POLICY="${FIXTURE_WIDE_DNS_POLICY:-}" WIDE_IPV6_POLICY="${FIXTURE_WIDE_IPV6_POLICY:-}" UDP_CARRY=0
AUTO_PROFILE="${FIXTURE_AUTO_PROFILE:-0}"
FORCE=1
NO_RUNTIME_EVENTS=0
TEMP_PATHS=()
detect_os_kind() { printf linux; }
default_client_helper_dir() { printf '%s/helpers' "$FIXTURE_ROOT"; }
resolve_existing_install_choice() { printf '%s' "${FIXTURE_CHOICE:-upgrade}"; }
install_binary() { [[ "$4" == preflight ]] || exit 90; PREFLIGHT_CLIENT_BINARY="$FIXTURE_CLIENT"; }
install_manifest_path_for_role() { printf ready > "$FIXTURE_MUTATION"; exit 77; }
apply_existing_install_choice() { printf forbidden > "$FIXTURE_MUTATION"; exit 91; }
prepare_client_config_boundary() { printf forbidden > "$FIXTURE_MUTATION"; exit 92; }
# Only these fixture-owned locations are allowed instead of real system paths.
device_service_identity_path() { [[ "$1" == "${FIXTURE_IDENTITY:-$FIXTURE_ROOT/identity}" || "$1" == "${FIXTURE_CONFIG_DIR:-$FIXTURE_ROOT/config}" ]]; }
install_device_full_wide_role() {
  [[ "$DEVICE_PRODUCT_MODE" == full-wide-tun && "$PRODUCT_MODE" == full-wide-tun ]] || exit 93
  [[ "$OPERATOR_MODE" == client-ipv6-tun-smoltcp && "$UDP_CARRY" == 1 && "$AUTO_PROFILE" == 0 ]] || exit 94
  [[ "$BUNDLE_PATH" == "$DEVICE_PUBLIC_BUNDLE" && -f "$BUNDLE_PATH/bundle.json" ]] || exit 95
  printf full-wide-public-preserved > "$FIXTURE_MUTATION"
  exit 78
}
auto_v2_device_input() {
  [[ "$AUTO_PROFILE" == 1 && "$AUTO_DEVICE_V2_REQUIRED" == 1 ]] || exit 96
  [[ "$DEVICE_BUNDLE_SCHEMA" == aegis_device_bundle_v2 && "$DEVICE_ONLINE" == 0 ]] || exit 96
  [[ "$1" == "$PREFLIGHT_CLIENT_BINARY" && "$2" == "$DEVICE_PUBLIC_BUNDLE" &&
     "$3" == "$FIXTURE_AUTO_MANAGED_IDENTITY" && "$4" == "$CONFIG_DIR" ]] || exit 96
  # This real CLI still validates the completed identity and public profile;
  # protected staging and V2 activation remain inert boundaries in this test.
  "$1" device bundle-ready --bundle-dir "$2" --identity-dir "$3" --device-id "$DEVICE_ID" >/dev/null || exit 96
  AUTO_V2_DEVICE_INPUT_PATH="$FIXTURE_ROOT/auto-input"
  mkdir -m 0700 "$AUTO_V2_DEVICE_INPUT_PATH"
  printf input-admitted > "$FIXTURE_AUTO_EVENTS"
}
auto_v2_install_and_release_package_lock() {
  [[ "$AUTO_PROFILE" == 1 && "$AUTO_DEVICE_V2_REQUIRED" == 1 && "$AUTO_DEVICE_V2_REQUESTED" == 1 ]] || exit 97
  [[ "$PRODUCT_MODE" == full-wide-tun && "$OPERATOR_MODE" == client-ipv6-tun-smoltcp && "$UDP_CARRY" == 1 ]] || exit 97
  [[ "$#" == 6 && "$1" == "$PREFIX" && "$2" == "$CONFIG_DIR" && "$3" == "$STATE_DIR" &&
     "$4" == /var/log/aegis-client && "$5" == /var/lib/aegis-client-logs/runtime/runtime-events.jsonl && "$6" == none ]] || exit 97
  [[ "$BUNDLE_PATH" == "$FIXTURE_ROOT/auto-input" && -d "$BUNDLE_PATH" &&
     "$(cat "$FIXTURE_AUTO_EVENTS")" == input-admitted ]] || exit 97
  printf '\nv2-handoff' >> "$FIXTURE_AUTO_EVENTS"
  exit 79
}
''' + function('device_absolute_path') + function('device_bundle_render') + function('device_relay_geneva_absent') + function('device_relay_geneva_preflight') + function('resolve_device_bundle_policy') + prepare + role + '\ninstall_client_role\n')
    env = os.environ | {'FIXTURE_ROOT': str(work), 'FIXTURE_CLIENT': str(diagnostic_client),
        'FIXTURE_MUTATION': str(marker), 'FIXTURE_UID': str(os.getuid())}
    initial = run(['bash', runner], env=env)
    assert 'Installation is pending' in initial.stdout
    assert not marker.exists()
    assert previous.read_text() == 'existing working config must not change during preparation'
    key = identity / 'device.key'
    first_inode = key.stat().st_ino
    first_key = key.read_bytes()
    run(['bash', runner], env=env)
    assert key.stat().st_ino == first_inode and key.read_bytes() == first_key
    status = json.loads(run([client, 'device', 'status', '--identity-dir', identity, '--json']).stdout)
    assert status['device_id'] == 'fixture-device' and status['phase'] == 'prepared'
    # Changing a public origin authority must fail even with an unchanged issuer CA.
    original_profile = (bundle / 'bundle.json').read_text()
    (bundle / 'bundle.json').write_text(original_profile.replace('origin.test', 'other.test'))
    run(['bash', runner], ok=False, env=env)
    assert not marker.exists()
    (bundle / 'bundle.json').write_text(original_profile)

    certificate = work / 'response.pem'
    registry = work / 'registry.json'
    invitation = work / 'invitation'
    operator = [server, 'device', '--registry', registry]
    run(operator + ['init'])
    run(operator + ['invite', '--device-id', 'fixture-device', '--token-out', invitation])
    run(operator + ['issue', '--csr', identity / 'device.csr', '--ca-cert', ca, '--ca-key', ca_key,
                    '--invitation-file', invitation, '--certificate-out', certificate])
    rejected = run(['bash', runner], ok=False, env=env | {'FIXTURE_CERTIFICATE': str(ca)})
    assert not marker.exists()
    assert 'Installation is pending' not in rejected.stdout
    completed = run(['bash', runner], ok=False, env=env | {'FIXTURE_CERTIFICATE': str(certificate)})
    assert completed.returncode == 77 and marker.read_text() == 'ready', completed.stderr
    assert key.stat().st_ino == first_inode and key.read_bytes() == first_key
    assert previous.read_text() == 'existing working config must not change during preparation'
    status = json.loads(run([client, 'device', 'status', '--identity-dir', identity, '--json']).stdout)
    assert status['phase'] == 'ready'
    rendered = list(identity.glob('.install-render.*/aegis-client.toml'))
    assert len(rendered) == 1
    import tomllib
    settings = tomllib.loads(rendered[0].read_text())
    assert settings['relay']['inner_tls']['key'] == str(identity / 'device.key')
    assert settings['relay']['inner_tls']['server_ca'] == str(config / 'inner-ca.pem')
    assert settings['relay']['ca_cert'] == str(config / 'ca.pem')
    assert settings['relay']['transport_priority'] == ['grpc_stream']
    assert settings['relay']['udp_transport_priority'] == []
    assert settings['relay']['auth_token'] == ''
    key_copies = [p for p in work.rglob('*') if p.is_file() and p.read_bytes() == first_key]
    assert key_copies == [key], key_copies
    assert key.stat().st_mode & 0o777 == 0o600
    assert identity.stat().st_mode & 0o777 == 0o700

    # The same real CA and parser generate a distinct public v2 profile. Its
    # explicit profile must preserve full-wide rather than use SOCKS rendering.
    # Default AUTO has its separate V2 handoff checks below.
    marker.unlink()
    wide_profile = work / 'wide-profile.json'
    wide_profile.write_text(json.dumps({'schema': 'aegis_device_bundle_v2',
        'product_mode': 'full-wide-tun', 'relay_server': '198.51.100.20:443',
        'outer_server_name': 'relay.test', 'inner_server_name': 'origin.test', 'udp': True}))
    wide_bundle = work / 'wide-bundle'
    wide_create = create.copy()
    wide_create[wide_create.index('--bundle-dir') + 1] = wide_bundle
    wide_create[wide_create.index('--profile') + 1] = wide_profile
    run(wide_create)
    explicit_wide = env | {'FIXTURE_BUNDLE': str(wide_bundle),
                           'FIXTURE_PRODUCT_MODE': 'full-wide-tun'}
    conflicts = {
        'PRODUCT_MODE': 'socks-only', 'OPERATOR_MODE': 'client-socks',
        'OPERATOR_TRANSPORT': 'h2', 'MASQUE_SERVER': 'other.test:443',
        'MASQUE_CA': str(ca), 'FRONTED_AUTHORITY': 'other.test',
        'GENEVA_STRATEGY_FILE': str(work / 'strategy.json'),
        'WIDE_UDP_POLICY': 'native', 'WIDE_DNS_POLICY': 'system',
        'WIDE_IPV6_POLICY': 'block',
    }
    for name, value in conflicts.items():
        untouched = work / ('refused-' + name.lower())
        rejected = run(['bash', runner], ok=False, env=explicit_wide | {
            'FIXTURE_IDENTITY': str(untouched),
            'FIXTURE_' + name: value})
        assert not untouched.exists() and not marker.exists(), (name, rejected.stderr)
        reason = ('Full-wide device policy is fixed' if name.startswith('WIDE_') else
                  'Device public profile conflicts with explicit mode or transport options')
        assert reason in rejected.stderr, (name, rejected.stderr)
        assert previous.read_text() == 'existing working config must not change during preparation'

    wide_identity = work / 'wide-identity'
    wide_env = explicit_wide | {'FIXTURE_IDENTITY': str(wide_identity),
                      'FIXTURE_DEVICE_ID': 'fixture-fullwide'}
    pending = run(['bash', runner], env=wide_env)
    assert 'Installation is pending' in pending.stdout and not marker.exists()
    wide_key = wide_identity / 'device.key'
    wide_original = (wide_key.stat().st_ino, wide_key.read_bytes())
    run(['bash', runner], env=wide_env)
    assert (wide_key.stat().st_ino, wide_key.read_bytes()) == wide_original
    wide_certificate = work / 'wide-response.pem'
    wide_invitation = work / 'wide-invitation'
    run(operator + ['invite', '--device-id', 'fixture-fullwide', '--token-out', wide_invitation])
    run(operator + ['issue', '--csr', wide_identity / 'device.csr', '--ca-cert', ca,
                    '--ca-key', ca_key, '--invitation-file', wide_invitation,
                    '--certificate-out', wide_certificate])
    completed = run(['bash', runner], ok=False,
                    env=wide_env | {'FIXTURE_CERTIFICATE': str(wide_certificate)})
    assert completed.returncode == 78 and marker.read_text() == 'full-wide-public-preserved'
    assert (wide_key.stat().st_ino, wide_key.read_bytes()) == wide_original
    assert not list(wide_identity.glob('.install-render.*')), 'full-wide reached legacy SOCKS renderer'
    assert previous.read_text() == 'existing working config must not change during preparation'
    copies = [p for p in work.rglob('*') if p.is_file() and p.read_bytes() == wide_original[1]]
    assert copies == [wide_key] and wide_key.stat().st_mode & 0o777 == 0o600

    marker.unlink()
    auto_identity = work / 'auto-identity'
    auto_config = work / 'auto-config'
    auto_state = work / 'auto-runtime'
    auto_config.mkdir()
    auto_state.mkdir()
    auto_events = work / 'auto-events'
    auto_env = env | {'FIXTURE_BUNDLE': str(wide_bundle),
        'FIXTURE_PRODUCT_MODE': 'auto', 'FIXTURE_AUTO_PROFILE': '1',
        'FIXTURE_CHOICE': 'none', 'FIXTURE_IDENTITY': str(auto_identity),
        'FIXTURE_AUTO_MANAGED_IDENTITY': str(auto_identity),
        'FIXTURE_CONFIG_DIR': str(auto_config), 'FIXTURE_STATE_DIR': str(auto_state),
        'FIXTURE_LOG_DIR': '/var/log/aegis-client', 'FIXTURE_AUTO_EVENTS': str(auto_events),
        'FIXTURE_DEVICE_ID': 'fixture-auto-fullwide'}
    unrebased_runner = work / 'unrebased-managed-identity.sh'
    unrebased_runner.write_text(runner.read_text().replace(prepare, unrebased_prepare))
    assert unrebased_runner.read_text() != runner.read_text()
    rejected = run(['bash', unrebased_runner], ok=False, env=auto_env)
    assert 'Automatic device V2 requires the separate managed identity directory.' in rejected.stderr
    assert not auto_identity.exists() and not auto_events.exists() and not marker.exists()
    for name, value in conflicts.items():
        untouched = work / ('auto-refused-' + name.lower())
        rejected = run(['bash', runner], ok=False, env=auto_env | {
            'FIXTURE_IDENTITY': str(untouched), 'FIXTURE_AUTO_MANAGED_IDENTITY': str(untouched),
            'FIXTURE_' + name: value})
        reason = ('Full-wide device policy is fixed' if name.startswith('WIDE_') else
                  'Device public profile conflicts with explicit mode or transport options')
        assert reason in rejected.stderr, (name, rejected.stderr)
        assert not untouched.exists() and not auto_events.exists() and not marker.exists()
    rejected = run(['bash', runner], ok=False, env=auto_env | {'FIXTURE_BUNDLE': str(bundle)})
    assert 'Automatic device installation requires an offline v2 full-wide profile' in rejected.stderr
    assert not auto_identity.exists() and not auto_events.exists() and not marker.exists()
    pending = run(['bash', runner], env=auto_env)
    assert 'Installation is pending' in pending.stdout and not marker.exists() and not auto_events.exists()
    auto_key = auto_identity / 'device.key'
    auto_original = (auto_key.stat().st_ino, auto_key.read_bytes())
    run(['bash', runner], env=auto_env)
    assert (auto_key.stat().st_ino, auto_key.read_bytes()) == auto_original
    auto_certificate, auto_invitation = work / 'auto-response.pem', work / 'auto-invitation'
    run(operator + ['invite', '--device-id', 'fixture-auto-fullwide', '--token-out', auto_invitation])
    run(operator + ['issue', '--csr', auto_identity / 'device.csr', '--ca-cert', ca,
                    '--ca-key', ca_key, '--invitation-file', auto_invitation,
                    '--certificate-out', auto_certificate])
    rejected = run(['bash', runner], ok=False, env=auto_env | {'FIXTURE_CERTIFICATE': str(ca)})
    assert not auto_events.exists() and not marker.exists()
    completed = run(['bash', runner], ok=False,
                    env=auto_env | {'FIXTURE_CERTIFICATE': str(auto_certificate)})
    assert completed.returncode == 79 and auto_events.read_text() == 'input-admitted\nv2-handoff'
    assert not marker.exists() and not list(auto_config.iterdir()) and not list(auto_state.iterdir())
    assert (auto_key.stat().st_ino, auto_key.read_bytes()) == auto_original
    assert not list(auto_identity.glob('.install-render.*'))
    copies = [p for p in work.rglob('*') if p.is_file() and p.read_bytes() == auto_original[1]]
    assert copies == [auto_key] and auto_key.stat().st_mode & 0o777 == 0o600
    assert auto_identity.stat().st_mode & 0o777 == 0o700
    assert previous.read_text() == 'existing working config must not change during preparation'

print('PASS: public-only producer; explicit SOCKS/full-wide pending/resume; trust pin; certificate gate; final identity references; one device key inode per profile; default AUTO offline-v2 V2 handoff; unmodified managed-identity refusal; unsupported AUTO v1 refusal; 20 specific override refusals before key creation; inert activation boundaries')
PY
