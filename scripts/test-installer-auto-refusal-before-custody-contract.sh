#!/usr/bin/env bash
# Execute only the extracted actual installer entry function. All mutation,
# service, binary and planner boundaries are inert recording/terminating stubs.
# This checks AUTO refusal ordering, not real config migration or native safety.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
python3 - "$ROOT" "${1:-$ROOT/install.sh}" <<'PY'
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path

source = Path(sys.argv[2]).read_text()
match = re.search(r'^install_client_role\(\) \{\n.*?^\}', source, re.M | re.S)
assert match, "actual install_client_role missing"
actual = match[0] + "\n"
stubs = r'''
record() { printf '%s\n' "$1" >> "$FIXTURE_EVENTS"; }
default_client_helper_dir() { printf '%s/lib/aegis/helpers' "$1"; }
resolve_existing_install_choice() { printf '%s' "$FIXTURE_CHOICE"; }
install_binary() {
  [[ "$4" == preflight ]] || { record unexpected-binary-write; return 98; }
  record binary-auth-abi-preflight
}
install_manifest_path_for_role() { printf '%s/install-manifest.json' "$2"; }
install_atomic_write() { record manifest-admission; }
prepare_client_config_boundary() {
  # Models the forbidden boundary effect in private synthetic state. No real
  # custody helper, systemctl, chown, migration or restart is ever executed.
  record boundary-stop
  printf '%s\n' migrated-fixture > "$1/aegis.toml"
  record boundary-migrate
  record boundary-restart
}
resolve_auto_profile() { record unexpected-legacy-planner; return 96; }
install_client_auto_v2() { record v2-coordinator-admission; return 97; }
auto_v2_install_and_release_package_lock() { install_client_auto_v2 "$@"; }
require_asset() { record asset-admission; }
preflight_wide_capture() { record unexpected-capture; return 95; }
apply_existing_install_choice() { record unexpected-purge; return 94; }
'''

with tempfile.TemporaryDirectory(prefix="aegis-auto-refusal-custody-") as tmp:
    base = Path(tmp)
    for case, choice, expected_error in (
        ("reinstall", "reinstall", "fresh automatic reinstall requires --bundle"),
        ("upgrade", "upgrade", "Existing client has no administrator-owned product profile"),
        ("staged-managed-upgrade", "upgrade", "Automatic activation requires the system service directory"),
        ("managed-upgrade", "upgrade", None),
        ("custom-log-root", "reinstall", "Automatic V2 uses its fixed protected runtime log directory"),
    ):
        work = base / case
        config, state = work / "config", work / "state"
        config.mkdir(parents=True)
        state.mkdir()
        sentinel = config / "aegis.toml"
        original = b"synthetic existing configuration\n"
        sentinel.write_bytes(original)
        if case in ("managed-upgrade", "staged-managed-upgrade"):
            (state / "wide-profile.json").write_text('{"synthetic": true}\n')
        events = work / "events"
        env = {
            "PATH": "/usr/bin:/bin", "LC_ALL": "C",
            "ROOT": str(work), "TMPDIR": str(work), "PREFIX": str(work / "prefix"),
            "CONFIG_DIR": str(config), "STATE_DIR": str(state),
            "LOG_DIR": str(work / "logs") if case == "custom-log-root" else "/var/log/aegis-client",
            "SYSTEMD_DIR": str(work / "units") if case == "staged-managed-upgrade" else "/etc/systemd/system",
            "ENV_DIR": str(work / "env"), "BUNDLE_PATH": "", "BUNDLE_URL_FILE": "",
            "CLIENT_PACKAGE": "",
            "DEVICE_ID": "", "DEVICE_CERTIFICATE": "", "DEVICE_IDENTITY_DIR": "",
            "DEVICE_INVITATION_FILE": "", "DEVICE_BUNDLE": "0", "FORCE": "1",
            "PRODUCT_MODE": "auto",
            "STAGE_AUTO_DEVICE_GUARD": "0",
            "AUTO_PROFILE": "1", "OPERATOR_MODE": "", "NO_RUNTIME_EVENTS": "0",
            "PREFLIGHT_CLIENT_BINARY": str(work / "never-executed-candidate"),
            "FIXTURE_CHOICE": choice, "FIXTURE_EVENTS": str(events),
        }
        result = subprocess.run(
            ["/bin/bash", "-c", "set -eu\n" + actual + stubs + "install_client_role"],
            env=env, capture_output=True, text=True, timeout=5,
        )
        recorded = events.read_text().splitlines() if events.exists() else []
        if case == "custom-log-root":
            assert result.returncode == 1, (case, "wrong refusal status", result.returncode, result.stderr)
            assert expected_error in result.stderr, (case, "wrong refusal reason", result.stderr)
            assert recorded == [], (case, "custom log root reached binary or custody", recorded)
            assert sentinel.read_bytes() == original, (case, "existing config changed")
            continue
        if case == "managed-upgrade":
            # The real entry must delegate to V2 before ANY legacy custody,
            # manifest, planner, purge or activation operation. The terminating
            # stub proves that boundary only; native installation is separate.
            assert result.returncode == 97, (case, "V2 coordinator not reached", result.returncode, result.stderr)
            assert recorded == ["binary-auth-abi-preflight", "v2-coordinator-admission"], (
                case, "AUTO bypassed V2 or crossed legacy mutation", recorded,
            )
            assert sentinel.read_bytes() == original, (case, "legacy custody mutated config")
            continue
        assert result.returncode == 1, (choice, "wrong refusal status", result.returncode)
        assert expected_error in result.stderr, (choice, "wrong refusal reason", result.stderr)
        assert "binary-auth-abi-preflight" in recorded, (choice, "lost binary admission")
        assert not any(x.startswith("boundary-") for x in recorded), (
            choice, "AUTO refusal crossed configuration custody", recorded,
        )
        assert sentinel.read_bytes() == original, (choice, "existing config changed")
        assert not any(x.startswith("unexpected-") for x in recorded), (
            choice, "refusal reached planner, purge, capture or replacement",
        )
        assert "planner-admission" not in recorded, (case, "refusal reached planner")
        assert "asset-admission" not in recorded, (case, "refusal reached asset admission")
    # Execute the actual passive preflight with a private path rebasing and
    # read-only PID1 fixture. No real service or installed path is changed.
    passive = list(re.finditer(
        r"^  python3 -I -B - <<'PY_AUTO_PASSIVE' \|\| return 1\n(.*?)^PY_AUTO_PASSIVE$",
        source, re.M | re.S))
    assert len(passive) == 1, "one fail-closed V2 passive preflight required"
    passive = passive[0]
    fixture = base / "passive-fixture"
    fixture.mkdir()
    fake_systemctl = fixture / "systemctl"
    fake_systemctl.write_text("#!" + sys.executable + "\n" + r'''
import json, os, sys
args=sys.argv[1:]
with open(os.environ['FIXTURE_CALLS'], 'a') as stream:
    stream.write(json.dumps(args) + '\n')
case=os.environ['FIXTURE_CASE']
if args[0]=='show':
    unit=args[1]
    facts={'Id':unit,'LoadState':'not-found','ActiveState':'inactive',
           'SubState':'dead','MainPID':'0','ControlPID':'0','ControlGroup':'',
           'NFileDescriptorStore':'0','FragmentPath':'','DropInPaths':'',
           'Triggers':'','NeedDaemonReload':'no','UnitFileState':''}
    dhcp=unit in ('aegis-device-dhcp-refresh.service','aegis-device-dhcp-refresh.timer')
    if dhcp and (case=='loaded-dhcp' or case.startswith('dhcp-')):
        facts.update(LoadState='loaded',
            FragmentPath=os.environ['FIXTURE_ROOT']+'/etc/systemd/system/'+unit,
            UnitFileState='disabled' if unit.endswith('.timer') else 'static',
            Triggers='aegis-device-dhcp-refresh.service' if unit.endswith('.timer') else '')
    if unit=='aegis-client.service' and case=='active':
        facts.update(LoadState='loaded',ActiveState='active',SubState='running',MainPID='111')
    if unit=='aegis-auto-guardian-watchdog.service' and case=='fdstore':
        facts['NFileDescriptorStore']='2'
    if unit=='aegis-client.service':
        if case=='missing-id': facts.pop('Id')
        if case=='unknown-load-state': facts['LoadState']='masked'
        if case=='control-pid': facts['ControlPID']='111'
        if case=='control-group': facts['ControlGroup']='/foreign'
        if case=='systemctl-failure': sys.exit(1)
    if dhcp:
        suffix='timer' if unit.endswith('.timer') else 'service'
        if case=='dhcp-'+suffix+'-active': facts.update(ActiveState='active',SubState='running')
        if case=='dhcp-'+suffix+'-fragment': facts['FragmentPath']='/foreign/'+unit
        if case=='dhcp-'+suffix+'-state': facts['UnitFileState']='enabled'
        if case=='dhcp-'+suffix+'-trigger': facts['Triggers']='foreign.service'
        if case=='dhcp-dropin': facts['DropInPaths']='/foreign/override.conf'
        if case=='dhcp-reload': facts['NeedDaemonReload']='yes'
    print('\n'.join(k+'='+v for k,v in facts.items()))
elif args[0]=='list-units':
    if os.environ['FIXTURE_CASE']=='private-unit': print('aegis-auto@'+'a'*64+'.service loaded active running')
elif args[0]=='list-jobs':
    if os.environ['FIXTURE_CASE']=='pending-job': print('1 aegis-client.service start running')
    if os.environ['FIXTURE_CASE']=='unrelated-job': print('1 unrelated.service start running')
else: sys.exit(98)
''')
    fake_systemctl.chmod(0o755)
    passive_source = passive[1].replace("'/usr/bin/systemctl'", repr(str(fake_systemctl)))
    for original_path in ('/etc/systemd/system/', '/var/lib/aegis-install/',
                          '/var/lib/aegis-auto/', '/run/aegis-installer-config-snapshots'):
        passive_source = passive_source.replace(original_path, str(fixture) + original_path)
    passive_path = fixture / 'preflight.py'
    passive_path.write_text(passive_source)
    protected = fixture / 'var/lib/aegis-install/client'
    protected.mkdir(parents=True)
    guard_unit = fixture / 'etc/systemd/system/aegis-device-egress-guard.service'
    guard_unit.parent.mkdir(parents=True)
    stopped = 'AUTO asset replacement requires authenticated stopped services'
    exact = 'AUTO DHCP passive unit configuration is not exact'
    generation = 'Existing AUTO generation requires authenticated recovery before asset replacement'
    cases = [
        ('clean', None, None), ('active', None, stopped), ('fdstore', None, stopped),
        ('private-unit', None, 'AUTO private owner must finish its authenticated stop before replacement'),
        ('pending-job', None, 'AUTO pending service job prevents asset replacement'),
        ('prior-receipt', protected / 'auto-guardian-install.json', generation),
        ('orphan-guard-unit', guard_unit, generation),
        ('orphan-guard-state', protected / 'device-guard.conf', generation),
        ('loaded-dhcp', None, None), ('unrelated-job', None, None),
        *[('dhcp-'+kind+'-'+field, None, stopped if field=='active' else exact)
          for kind in ('service', 'timer') for field in ('active', 'fragment', 'state', 'trigger')],
        ('dhcp-dropin', None, exact), ('dhcp-reload', None, exact),
        *[(case, None, stopped) for case in ('missing-id','unknown-load-state','control-pid','control-group')],
        ('systemctl-failure', None, 'AUTO passive asset preflight refused'),
    ]
    calls = fixture / 'calls.jsonl'
    for case, present, error in cases:
        calls.write_text('')
        if present:
            present.write_text('retained private fixture\n')
        result = subprocess.run([sys.executable, '-I', '-B', str(passive_path)],
            env={'PATH':'/usr/bin:/bin','FIXTURE_CASE':case,
                 'FIXTURE_ROOT':str(fixture),'FIXTURE_CALLS':str(calls)}, capture_output=True,
            text=True, timeout=5)
        assert (result.returncode == 0) == (error is None), (case, result.stderr)
        if error is not None:
            assert error in result.stderr, (case, 'wrong refusal', result.stderr)
        recorded = [json.loads(line) for line in calls.read_text().splitlines()]
        assert all(row[0] in ('show','list-units','list-jobs') for row in recorded), (case, recorded)
        if error is None:
            assert [row[1] for row in recorded if row[0]=='show'] == [
                'aegis-client.service','aegis-device-egress-guard.service',
                'aegis-device-dhcp-refresh.service','aegis-device-dhcp-refresh.timer',
                'aegis-auto-guardian.service','aegis-auto-guardian-watchdog.service'], (case, recorded)
            assert [row[0] for row in recorded] == ['show']*6 + ['list-units','list-jobs'], (case, recorded)
        if present:
            assert present.read_text() == 'retained private fixture\n'
            present.unlink()
    print(f'PASS: {len(cases)} actual passive preflight cases; exact DHCP units and all active/queued/FD-store/prior-receipt/orphan-guard refusals; read-only inert PID1 only')
    print("PASS: three AUTO refusals precede custody; managed control delegates to V2 before legacy mutation; inert effects only")
PY
