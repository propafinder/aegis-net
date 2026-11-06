#!/usr/bin/env bash
# Actual installer functions; all operations after admission terminate in stubs.
# No installer top-level dispatch, host service, routing or networking is run.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd -P)"
python3 -I - "${ROOT}" <<'PY'
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

root = Path(sys.argv[1])
source = (root / 'install.sh').read_text()


def function(name, required=True):
    match = re.search(r'^' + name + r'\(\) \{\n.*?^\}', source, re.M | re.S)
    if match is None:
        assert not required, name
        return ''
    return match[0] + '\n'


# The predecessor has no preflight function. Its actual caller/activation bodies
# execute unchanged; absence is not replaced by a model of the proposed gate.
actual = function('preflight_wide_capture', required=False)
actual += function('activate_wide_capture') + function('install_client_role')
stubs = r'''
id() { printf '%s\n' "$FIXTURE_UID"; }
checkpoint() { printf '%s\n' "$1" >> "$MUTATIONS"; exit 98; }
mkdir() {
  if [[ "$EXPECTED_EXIT" == 98 ]]; then checkpoint helper_stage; fi
  printf helper_stage >> "$MUTATIONS";
  return 0;
}
install() { printf install_copy >> "$MUTATIONS"; return 1; }
cp() { printf fallback_copy >> "$MUTATIONS"; return 1; }
install_copy_file() {
  printf root_state_copy >> "$MUTATIONS";
  [[ -f "$1" ]];
}
default_client_helper_dir() { printf '%s/helpers' "$PREFIX"; }
resolve_existing_install_choice() { printf '%s' "$CHOICE"; }
apply_existing_install_choice() {
  if [[ "$CHOICE" == cancel ]]; then exit 0; fi
  checkpoint purge;
}
install_binary() {
  if [[ "${4:-}" == preflight ]]; then
    printf binary_preflight >> "$OBSERVATIONS";
    return 0;
  fi
  checkpoint binary_install;
}
install_manifest_path_for_role() { printf '%s/manifest.json' "$METADATA"; }
install_atomic_write() {
  [[ "${4:-}" == validate ]] || checkpoint metadata_write;
  printf metadata_validate >> "$OBSERVATIONS";
}
prepare_client_config_boundary() { checkpoint config_custody; }
resolve_downloaded_bundle() { checkpoint download; }
deactivate_existing_wide_boot_units() { checkpoint deactivate; }
command_not_found_handle() {
  printf 'unexpected fixture command: %s\n' "$1" >&2;
  exit 96;
}
'''

modes = {
    'client-wide-redirect': 'setup-wide-linux-redirect.sh',
    'client-wide-tproxy': 'setup-wide-linux-tproxy.sh',
    'client-wide-nfqueue-observer': 'setup-wide-linux-redirect.sh',
    'client-ipv6-tun-smoltcp': 'setup-wide-linux-redirect.sh',
}
results = []
with tempfile.TemporaryDirectory(prefix='aegis-wide-activation-contract-') as raw:
    work = Path(raw)
    package = work / 'package'
    (package / 'scripts/lib').mkdir(parents=True)
    config = work / 'config'
    config.mkdir()
    sentinel = config / 'aegis.toml'
    sentinel.write_text('existing installation remains unchanged\n')
    state_asset = package / 'scripts/lib/root-state.sh'
    helper_stage = work / 'persisted'
    mutations, observations = work / 'mutations', work / 'observations'
    base_env = {
        **os.environ, 'ROOT': str(package), 'PREFIX': str(work / 'prefix'),
        'CONFIG_DIR': str(config), 'STATE_DIR': str(work / 'state'),
        'LOG_DIR': str(work / 'logs'), 'SYSTEMD_DIR': str(work / 'units'),
        'ENV_DIR': str(work / 'env'), 'AEGIS_WIDE_LIB_DIR': str(helper_stage),
        'METADATA': str(work / 'metadata'), 'MUTATIONS': str(mutations),
        'OBSERVATIONS': str(observations), 'CONFIG_PATH': str(sentinel),
        'BUNDLE_PATH': '', 'BUNDLE_URL': '', 'BUNDLE_URL_FILE': '', 'DEVICE_ID': '',
        'DEVICE_CERTIFICATE': '', 'DEVICE_IDENTITY_DIR': '',
        'DEVICE_INVITATION_FILE': '', 'DEVICE_BUNDLE': '0',
        'STAGE_AUTO_DEVICE_GUARD': '0', 'STAGE_AUTO_OWNER_RECEIPT': '',
        'PRODUCT_MODE': 'wide-redirect-safe', 'OPERATOR_MODE': '',
        'AUTO_PROFILE': '0', 'FORCE': '1', 'UDP_CARRY': '0',
        'NO_RUNTIME_EVENTS': '0', 'CHOICE': 'upgrade',
        'PREFLIGHT_CLIENT_BINARY': '/fixture/binary-preflight-only',
    }

    def run(name, entry, mode, uid, asset, expected, choice='upgrade'):
        for path in (mutations, observations, state_asset):
            path.unlink(missing_ok=True)
        for helper in set(modes.values()):
            path = package / 'scripts' / helper
            if path.is_dir():
                path.rmdir()
            else:
                path.unlink(missing_ok=True)
        state_asset.write_text('# inert root-state fixture; never executed\n')
        state_asset.chmod(0o644)
        helper = package / 'scripts' / modes.get(mode, 'unused-helper.sh')
        if asset == 'directory':
            helper.mkdir()
        elif asset != 'missing':
            helper.write_text('#!/bin/bash\nexit 97 # never executed\n')
            helper.chmod(0o644 if asset == 'not-executable' else 0o755)
        if asset == 'missing-root-state':
            state_asset.unlink()
        call = 'activate_wide_capture "$CONFIG_PATH" "$OPERATOR_MODE"' if entry == 'activate' else 'install_client_role'
        result = subprocess.run(
            ['/bin/bash', '-c', 'set +e\nset -u\n' + actual + stubs +
             'if ' + call + '; then status=0; else status=$?; fi\nexit "$status"'],
            env={**base_env, 'OPERATOR_MODE': mode, 'FIXTURE_UID': uid, 'CHOICE': choice,
                 'EXPECTED_EXIT': str(expected)},
            capture_output=True, text=True, timeout=5,
        )
        mutation_text = mutations.read_text() if mutations.exists() else ''
        observation_text = observations.read_text() if observations.exists() else ''
        reasons = []
        if result.returncode != expected:
            reasons.append(f'exit={result.returncode}, expected={expected}')
        if expected == 1 and (mutation_text or observation_text):
            reasons.append('refusal reached mutation or later preflight')
        if expected == 0 and (mutation_text or observation_text):
            reasons.append('noncapture/cancel reached mutation')
        if expected == 98 and not mutation_text:
            reasons.append('valid predecessor path did not reach owned admission checkpoint')
        if sentinel.read_text() != 'existing installation remains unchanged\n':
            reasons.append('config sentinel changed')
        if helper_stage.exists():
            reasons.append('persisted helper tree created')
        row = {'case': name, 'entry': entry, 'mode': mode, 'expected_exit': expected,
               'actual_exit': result.returncode, 'passed': not reasons,
               'failure_reasons': reasons, 'mutation_witness': mutation_text,
               'observation_witness': observation_text, 'stderr': result.stderr}
        results.append(row)
        print(json.dumps(row, sort_keys=True))

    for mode in modes:
        run(mode + '-activate-nonroot', 'activate', mode, '1000', 'valid', 1)
        run(mode + '-caller-nonroot', 'caller', mode, '1000', 'valid', 1)
        run(mode + '-activate-valid', 'activate', mode, '0', 'valid', 98)
        run(mode + '-caller-valid', 'caller', mode, '0', 'valid', 98)
    for asset in ('missing', 'not-executable', 'directory', 'missing-root-state'):
        run(asset + '-activate', 'activate', 'client-wide-redirect', '0', asset, 1)
        run(asset + '-caller', 'caller', 'client-wide-redirect', '0', asset, 1)
    for mode in ('client-socks', 'client-passthrough', ''):
        run('noncapture-' + mode, 'activate', mode, '1000', 'missing', 0)
    run('cancel-preserved', 'caller', 'client-wide-redirect', '1000', 'missing', 0, 'cancel')
    run('socks-caller-preserved', 'caller', 'client-socks', '1000', 'missing', 98)

failed = [row for row in results if not row['passed']]
print(json.dumps({'cases': len(results), 'passed': len(results) - len(failed),
                  'failed': len(failed), 'scope': 'actual installer function/caller with inert mutation checkpoints; no host activation'}, sort_keys=True))
raise SystemExit(1 if failed else 0)
PY
