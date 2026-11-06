#!/usr/bin/env bash
# Source orchestration contract only; this does not run or accept TPROXY traffic.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
python3 - "${ROOT}" "$@" <<'PY'
import ast
import hashlib
import json
import os
import pathlib
import re
import subprocess
import sys
import tempfile
import textwrap

root = pathlib.Path(sys.argv[1])
if len(sys.argv) == 2:
    workflow = root / '.github/workflows/ci.yml'
elif len(sys.argv) == 4 and sys.argv[2] == '--workflow':
    workflow = pathlib.Path(sys.argv[3])
else:
    raise SystemExit('usage: test-ci-tproxy-shared-build-contract.sh [--workflow PATH]')

def require(condition, message):
    if not condition:
        raise SystemExit('TPROXY shared build CI contract: ' + message)

def canonical_ast(value):
    """Retain every node/field, including empty fields, independently of dump defaults."""
    if isinstance(value, ast.AST):
        fields = {name: getattr(value, name, None) for name in value._fields}
        # Python 3.12 added this field. Older parsers cannot parse type parameter
        # syntax, so their missing field is precisely the empty parameter list.
        # Nonempty parameters and all other fields are retained, never ignored.
        if isinstance(value, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            fields.setdefault('type_params', [])
        return {'node': type(value).__name__,
                'fields': {name: canonical_ast(item) for name, item in fields.items()}}
    if isinstance(value, list):
        return [canonical_ast(item) for item in value]
    return value

def assertion_fingerprint(source):
    tree = canonical_ast(ast.parse(textwrap.dedent(source)))
    encoded = json.dumps(tree, sort_keys=True, ensure_ascii=True,
                         allow_nan=False, separators=(',', ':')).encode('ascii')
    return hashlib.sha256(encoded).hexdigest()

require(workflow.stat().st_size <= 1024 * 1024, 'workflow input too large')
text = workflow.read_text()
match = re.search(r'^  rust:\n(.*?)(?=^  [A-Za-z0-9_-]+:\n|\Z)', text, re.M | re.S)
require(match is not None, 'Rust job missing')
job = match.group(1)
starts = list(re.finditer(r'^      - name: (.+)$', job, re.M))
steps = {}
for index, start in enumerate(starts):
    name = start.group(1).strip().strip('\"\'')
    require(name not in steps, 'duplicate step name: ' + name)
    end = starts[index + 1].start() if index + 1 < len(starts) else len(job)
    steps[name] = (start.start(), job[start.start():end])

# Fingerprint the existing executed Python assertion ASTs, not whitespace or
# comments. Weakening/removing an assertion requires an explicit contract change.
cases = [
    ('DNS smoke (xtables)', 'dns-xtables', 'dns', None, None,
     ['92e710ad979b43327d1a33d3e7e7991116bcf4e6e36162d444a337a1299d1604']),
    ('DNS smoke (nft)', 'dns-nft', 'dns', None, 'nft',
     ['84b106915f02281283b8161e93d96eacc94e9e88b66993e112b03b3ec8390984']),
    ('DNS IPv6 smoke', 'dns-ipv6', 'dns_ipv6', 'ipv6', None,
     ['8aa85c5cc1a43bef427da4face1d326214c29c39c1d313b8b5e5b5403b425f81']),
    ('UDP preview smoke', 'udp-preview', 'udp_preview', None, None, []),
    ('generic UDP smoke (xtables)', 'generic-udp-xtables', 'generic_udp', None, None,
     ['44151d4f002a9ede990bb3cb3c11cf2e2144818024d951d6111c6936af7ca587',
      '6859d4c12b4659e277da38a82b34359fe112a731fa2fcafbda93c3fa38105578']),
    ('generic UDP smoke (nft)', 'generic-udp-nft', 'generic_udp', None, 'nft',
     ['7e8408663beac453677286350c1213e20e6b6520e26d6b4dcac91f621aea4d6c',
      '6859d4c12b4659e277da38a82b34359fe112a731fa2fcafbda93c3fa38105578']),
    ('generic UDP IPv6 smoke', 'generic-udp-ipv6', 'generic_udp', 'ipv6', None,
     ['8859c73900c741983795baad154382b0ca3309cce446c36cac5d33ac2b058fd5',
      '2ac870b7509b78f336174388d8a4e67e812f13450c3dc055bf373ae6dc32016b']),
    ('UDP preview drop smoke', 'udp-preview-drop', 'udp_preview_drop', None, None,
     ['c95bb2e7fd7c8571167d045be5ce0aaa3f86b4cf3e60bd509acbe3e4690eb786']),
]
names = ['Guarded: Linux TPROXY ' + case[0] for case in cases]
actual = [name for name, (_, body) in steps.items()
          if name.startswith('Guarded: Linux TPROXY ')
          and re.search(r'^          guarded_smoke_status_init ', body, re.M)]
require(actual == names, 'exact eight ordered guarded cases must remain')
prep_name = 'Guarded: build Linux TPROXY smoke client'
require(prep_name in steps, 'actual prebuilt client step missing')
prep_position, prep = steps[prep_name]
metadata_name = 'Build trusted metadata CLI for installer contracts'
require(metadata_name in steps, 'trusted metadata source build missing')
metadata_position, metadata = steps[metadata_name]
require(metadata_position < prep_position, 'trusted metadata source build must precede smokes')
require('cargo build --locked -p aegis-client -p aegis-measure --bins' in metadata
        and 'bash scripts/test-root-state-boundary.sh' in metadata,
        'trusted metadata CLI must be built from actual source and checked')
require(re.search(r'--(?:features|no-default-features|release)\b|CARGO_TARGET_DIR\s*=', metadata) is None,
        'trusted metadata source build must retain default target/features')
for fragment in ["if: env.RUN_LINUX_EXTENDED == 'true'",
                 'export CARGO_TARGET_DIR="${GITHUB_WORKSPACE}/target"',
                 'cargo build --locked -p aegis-client -p aegis-server -p aegis-measure --bins',
                 'client_bin="${GITHUB_WORKSPACE}/target/debug/aegis-client"',
                 'test -x "${client_bin}"',
                 "printf 'AEGIS_CLIENT_BIN=%s\\n' \"${client_bin}\" >> \"${GITHUB_ENV}\""]:
    require(fragment in prep, 'prebuilt client source provenance missing: ' + fragment)
require(re.search(r'--(?:features|no-default-features|release)\b', prep) is None,
        'prebuilt client must retain default source build target/features')
require(re.findall(r'^          export CARGO_TARGET_DIR=(.+)$', prep, re.M)
        == ['"${GITHUB_WORKSPACE}/target"'], 'prebuild must use the shared base target')
cleanup = re.search(r'(?m)^          sudo find "\$\{GITHUB_WORKSPACE\}/target"(?:[^\n]*\\\n)*[^\n]*', prep)
require(cleanup is not None, 'bounded legacy child-target cleanup missing')
cleanup = cleanup.group(0)
require('-mindepth 1' in cleanup and '-maxdepth 1' in cleanup and '-type d' in cleanup
        and "-name 'ci-linux-tproxy-*'" in cleanup
        and re.search(r'-exec rm -rf (?:-- )?\{\} \+', cleanup)
        and '! -name' not in cleanup,
        'cleanup must select only named immediate legacy target children')
require(prep.find(cleanup) < prep.find('cargo build --locked'),
        'legacy cleanup must precede actual shared build')

for name, (_, case_id, protocol, family, backend, hashes) in zip(names, cases):
    position, body = steps[name]
    require(prep_position < position, 'prebuilt client must precede ' + name)
    require("if: env.RUN_LINUX_EXTENDED == 'true'" in body, 'guard changed: ' + name)
    preserved = re.findall(r'^          sudo --preserve-env=([^\s]+)', body, re.M)
    require(len(preserved) == 1
            and {'CARGO_PROFILE_DEV_DEBUG', 'CARGO_PROFILE_TEST_DEBUG'}
            <= set(preserved[0].split(',')),
            'sudo must retain the job Cargo debug-info profile: ' + name)
    require('continue-on-error:' not in body, 'failure cannot be ignored: ' + name)
    require('sudo find "${GITHUB_WORKSPACE}/target"' not in body,
            'case cannot discard the shared build or legacy targets: ' + name)
    require(re.findall(r'^          export CARGO_TARGET_DIR=(.+)$', body, re.M)
            == ['"${GITHUB_WORKSPACE}/target"'], 'shared actual base target missing: ' + name)
    require(re.search(r'--(?:features|no-default-features|release)\b', body) is None,
            'case cannot alter build features/profile: ' + name)
    expected = {'AEGIS_WIDE_SMOKE_PROTOCOL': protocol, 'AEGIS_WIDE_STARTUP_WAIT_SECS': '5'}
    if protocol not in ('udp_preview', 'udp_preview_drop'):
        expected['AEGIS_WIDE_SMOKE_HOST_SHAPE'] = 'github_hosted'
        expected['AEGIS_WIDE_SMOKE_CONTRACT_ARTIFACT'] = '"${contract_artifact}"'
    if family:
        expected['AEGIS_WIDE_SMOKE_IP_FAMILY'] = family
    if backend:
        expected['AEGIS_WIDE_FIREWALL_BACKEND'] = backend
    if protocol == 'generic_udp':
        expected['AEGIS_WIDE_GENERIC_UDP_TARGET_PORT'] = '54321'
        expected['AEGIS_WIDE_SMOKE_RUNTIME_EVENTS_ARTIFACT'] = '"${runtime_events_artifact}"'
    if protocol in ('udp_preview', 'udp_preview_drop'):
        expected['AEGIS_WIDE_UDP_PREVIEW_PORT'] = '5353'
    if protocol == 'udp_preview_drop':
        expected['AEGIS_WIDE_UDP_PREVIEW_DROP_TARGET_PORT'] = '5300'
        expected['AEGIS_WIDE_SMOKE_RUNTIME_EVENTS_ARTIFACT'] = '"${runtime_events_artifact}"'
    assignments = re.findall(r'^              (AEGIS_[A-Z0-9_]+)=(.*?) \\$', body, re.M)
    require(len(assignments) == len(expected) and dict(assignments) == expected,
            'case runtime arguments changed: ' + name)
    for fragment in ['set -euo pipefail', 'guarded_smoke_status_init ' + case_id,
                     'sudo --preserve-env=PATH,HOME,CARGO_HOME,RUSTUP_HOME,CARGO_TARGET_DIR,TMPDIR,AEGIS_CLIENT_BIN',
                     'timeout 300 bash scripts/smoke-wide-linux-tproxy.sh',
                     'status=$?', 'if [[ "${status}" -eq 124 ]]; then',
                     'guarded_smoke_status_write "failed:124"',
                     'guarded_smoke_status_write "passed"']:
        require(fragment in body, 'bounded status handling missing: ' + name)
    require(body.count('timeout 300 bash scripts/smoke-wide-linux-tproxy.sh') == 1,
            'case must invoke one bounded actual smoke: ' + name)
    require('guarded_smoke_artifacts_init' in body and 'guarded_smoke_artifacts_cleanup' in body,
            'owned root receipt allocation and cleanup missing: ' + name)
    expected_exit = '32' if protocol == 'udp_preview_drop' else '0'
    require('if [[ "${status}" -ne ' + expected_exit + ' ]]; then' in body,
            'positive/negative outcome check changed: ' + name)
    if protocol != 'udp_preview_drop':
        require('exit "${status}"' in body, 'actual failure must propagate: ' + name)
    else:
        require('exit 1' in body, 'negative case must reject unexpected success: ' + name)
    for artifact in ('contract_artifact', 'runtime_events_artifact'):
        if '"${' + artifact + '}"' in expected.values():
            leaf = 'contract.json' if artifact == 'contract_artifact' else 'runtime-events.jsonl'
            require(artifact + '="${GUARDED_SMOKE_ARTIFACT_DIR}/' + leaf + '"' in body,
                    'private root receipt path missing: ' + name)
    scripts = re.findall(r"^          python3[^\n]* <<'PY'\n(.*?)^          PY\s*$", body, re.M | re.S)
    actual_hashes = [assertion_fingerprint(s) for s in scripts]
    require(actual_hashes == hashes, 'actual runtime assertions changed: ' + name)

smoke = (root / 'scripts/smoke-wide-linux-tproxy.sh').read_text()
# Execute the actual apply invocation at its privilege boundary. A private
# endpoint records the received path; it performs no firewall or route work.
# This catches a missing handoff even when doctor/probe receive the config.
apply_start = smoke.index('echo "Applying TPROXY helper on interface ')
apply_end = smoke.index('\nwrite_smoke_contract_artifact\n', apply_start)
apply_command = smoke[apply_start:apply_end]
with tempfile.TemporaryDirectory(prefix='aegis-smoke-config-handoff-') as directory:
    fixture = pathlib.Path(directory)
    (fixture / 'bin').mkdir()
    (fixture / 'scripts').mkdir()
    sudo = fixture / 'bin/sudo'
    sudo.write_text('#!/usr/bin/env bash\nexec env "$@"\n')
    sudo.chmod(0o700)
    helper = fixture / 'scripts/setup-wide-linux-tproxy.sh'
    helper.write_text('''#!/usr/bin/env bash
set -euo pipefail
[[ "$1" == apply ]]
[[ "${AEGIS_CLIENT_CONFIG:-}" == "${EXPECTED_CLIENT_CONFIG}" ]]
[[ -f "${AEGIS_CLIENT_CONFIG}" ]]
printf '%s\\n' "${AEGIS_CLIENT_CONFIG}" > "${HANDOFF_RECEIPT}"
''')
    config = fixture / 'client config.toml'
    config.write_text('mode = "relay"\n')
    receipt = fixture / 'received-path'
    env = dict(os.environ, PATH=str(fixture / 'bin') + os.pathsep + os.environ['PATH'],
               ROOT=str(fixture), CFG_PATH=str(fixture / 'caller-temp.toml'),
               ADMIN_CFG_PATH=str(config), EXPECTED_CLIENT_CONFIG=str(config),
               HANDOFF_RECEIPT=str(receipt), HELPER_APPLY_LOG=str(fixture / 'apply.log'),
               VETH_HOST='aegis-test0', WIDE_PORT='15080', FWMARK='1', ROUTE_TABLE='100',
               SMOKE_IP_FAMILY='ipv4', FIREWALL_BACKEND='nft', ENABLE_DNS_PREVIEW='1',
               DNS_PORT='53', UDP_CAPTURE_CONTRACT='preview_allowlist_only',
               FORCE_ALL_UDP_TPROXY='0', UDP_PREVIEW_PORTS='')
    env.pop('AEGIS_CLIENT_CONFIG', None)
    result = subprocess.run(['bash', '-euo', 'pipefail', '-c', apply_command],
                            env=env, capture_output=True, text=True, timeout=10)
    require(result.returncode == 0 and receipt.is_file()
            and receipt.read_text() == str(config) + '\n',
            'actual apply must pass its administrative config across sudo, including spaces')
print('PASS: actual smoke apply hands its administrative config across sudo before firewall work')
staging = (root / 'scripts/lib/smoke-root-state-client.sh').read_text()
ordered = ['SMOKE_CARGO_TARGET_DIRECTORY="$(aegis_smoke_cargo_target_directory)"',
           '\nensure_aegis_measure_run_bin\n', 'cargo build -p aegis-server',
           'cargo build -p aegis-client -p aegis-server',
           'aegis_smoke_stage_root_state_client "${CLIENT_BIN_OVERRIDE}" "${AEGIS_MEASURE_RUN_BIN}"',
           '\nrun_preflight\n',
           '"${SMOKE_CARGO_TARGET_DIRECTORY}/debug/aegis-server" --config "${SERVER_CFG}"']
positions = [smoke.find(fragment) for fragment in ordered]
require(all(position >= 0 for position in positions) and positions == sorted(positions),
        'actual source build, trusted staging and runtime ordering changed')
for fragment in ['AEGIS_MEASURE_RUN_BIN="${SMOKE_CARGO_TARGET_DIRECTORY}/debug/aegis-measure"',
                 'cargo build --manifest-path "${ROOT}/Cargo.toml" -p aegis-measure',
                 'CLIENT_BIN_OVERRIDE="${SMOKE_CARGO_TARGET_DIRECTORY}/debug/aegis-client"',
                 'CLIENT_BIN_OVERRIDE="${AEGIS_CLIENT_BIN}"', 'SERVER_PID="$!"', 'CLIENT_PID="$!"']:
    require(fragment in smoke, 'actual binary/PID provenance missing: ' + fragment)
for fragment in ['metadata --manifest-path "${ROOT}/Cargo.toml"',
                 '--no-deps --offline --format-version 1', 'sha256sum -- "$source"',
                 'stage --source "$source" --sha256 "$digest" --binary-name "$name"',
                 'export AEGIS_ROOT_STATE_CLIENT="$AEGIS_SMOKE_ROOT_STATE_DIRECTORY/aegis-client"',
                 'export AEGIS_CLIENT_BIN="$AEGIS_ROOT_STATE_CLIENT"',
                 'aegis_root_state_init', 'aegis_root_trusted_executable',
                 'export AEGIS_MEASURE_RUN_BIN="$AEGIS_MEASURE_BIN"']:
    require(fragment in staging, 'trusted metadata provenance missing: ' + fragment)
print('PASS: eight bounded TPROXY cases share the actual base Cargo build target; runtime assertions and trusted source-binary staging retained')
PY
