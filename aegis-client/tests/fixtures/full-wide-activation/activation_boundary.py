"""Execute the real installer identity gate; stop before privileged metadata.

Only device inspection/recovery/status are forwarded to the supplied real CLI.
The first privileged metadata call returns an intentional sentinel failure.
No phase is synthesized, and no networking/service command is permitted.
For accepted staging states, also exercise real bundle rendering and the
read-only managed config validator in the private synthetic workspace.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys

root, client, temporary, bundle, identity = map(Path, sys.argv[1:6])
device_id, expected = sys.argv[6:8]
assert len(sys.argv) == 8 and expected in ("ready", "runtime_recovery_required", "refuse")
temporary = temporary.resolve(strict=True)
assert temporary.stat().st_uid == os.geteuid() and temporary.stat().st_mode & 0o077 == 0
for path in (bundle, identity):
    assert path.resolve(strict=True).is_relative_to(temporary)
source = (root / "install.sh").read_text()
names = ("device_recover_online_local", "activate_device_full_wide_capture")
functions = []
for name in names:
    match = re.search(r"^" + name + r"\(\) \{\n.*?^\}", source, re.M | re.S)
    assert match, name
    functions.append(match[0])

calls = temporary / "activation-calls.jsonl"
sentinel = temporary / "activation-boundary-reached"
wrapper = temporary / "local-cli-only"
wrapper.write_text("#!" + sys.executable + "\n" + r'''
import json,os,pathlib,subprocess,sys
a=sys.argv[1:];base=pathlib.Path(os.environ['FIXTURE_ROOT'])
def record(value):
    with (base/'activation-calls.jsonl').open('a') as f:f.write(json.dumps(value)+'\n')
if a[:3]==['profile','metadata','validate']:
    assert a==['profile','metadata','validate','--path','/var/lib/aegis-install/client/device-guard.conf']
    (base/'activation-boundary-reached').write_text('intentional stop before privileged metadata\n')
    record({'command':a[:3],'sentinel':True})
    sys.exit(77)
assert a[:2] in (['device','bundle-inspect'],['device','recover-local'],['device','status']),a[:2]
p=subprocess.run([os.environ['REAL_CLIENT'],'--diagnostic-logs',*a],capture_output=True,text=True,timeout=20)
record({'command':a[:2],'returncode':p.returncode,'response':json.loads(p.stdout) if p.returncode==0 else None})
sys.stdout.write(p.stdout);sys.stderr.write(p.stderr);sys.exit(p.returncode)
''')
wrapper.chmod(0o700)
script = temporary / "activation.sh"
script.write_text("set -euo pipefail\n" + "\n".join(functions) + r'''
deny_external_action() { echo 'unexpected privileged/network action' >&2; return 98; }
systemctl() { deny_external_action; }
curl() { deny_external_action; }
mktemp() { deny_external_action; }
install_copy_file() { deny_external_action; }
install_atomic_write() { deny_external_action; }
install_device_egress_guard_units() { deny_external_action; }
activate_device_full_wide_capture "$PUBLIC_BUNDLE" "$IDENTITY" /etc/aegis/client/aegis.toml "$FIXTURE_ROOT/assessment.conf"
''')
environment = dict(os.environ, FIXTURE_ROOT=str(temporary), REAL_CLIENT=str(client),
                   AEGIS_ROOT_STATE_CLIENT=str(wrapper), AEGIS_WIDE_LIB_DIR=str(temporary / "unused-helpers"),
                   DEVICE_ONLINE="1", DEVICE_ID=device_id, PUBLIC_BUNDLE=str(bundle), IDENTITY=str(identity))
# Catch accidental use of the preflight binary instead of the bound installed CLI.
environment["PREFLIGHT_CLIENT_BINARY"] = str(temporary / "missing-preflight-client")
environment.pop("BASH_ENV", None)
environment.pop("ENV", None)
outcome = subprocess.run(["/bin/bash", str(script)], env=environment,
                         capture_output=True, text=True, timeout=60)
assert outcome.returncode != 0, "fixture must stop before privileged activation"
events = [json.loads(line) for line in calls.read_text().splitlines()]
assert events[0]["command"] == ["device", "bundle-inspect"] and events[0]["returncode"] == 0
assert len(events) >= 2 and events[1]["command"] == ["device", "recover-local"], (events, outcome.stderr)
if expected == "refuse":
    assert events[1]["returncode"] != 0 and not sentinel.exists() and len(events) == 2, events
else:
    assert events[1]["returncode"] == 0, (events, outcome.stderr)
    response = events[1]["response"]
    assert response["schema"] == "aegis_device_local_recovery_v1" and response["phase"] == expected, response
    assert response["repaired"] is (expected == "ready")
    assert response["pending_request"] is (expected == "runtime_recovery_required")
    assert sentinel.exists() and len(events) == 3 and events[2]["sentinel"] is True, events
assert "unexpected privileged/network action" not in outcome.stderr
staged_config_valid = False
config_validation_result = "not_reached"
if expected != "refuse":
    config_dir = temporary / "rendered-config"
    config_dir.mkdir(mode=0o700)
    for source_name, installed_name in (("outer-ca.pem", "ca.pem"),
                                         ("inner-ca.pem", "inner-ca.pem")):
        destination = config_dir / installed_name
        with destination.open("xb") as output:
            output.write((bundle / source_name).read_bytes())
        destination.chmod(0o600)
    config = config_dir / "aegis.toml"
    render = subprocess.run(
        [str(client), "--diagnostic-logs", "device", "bundle-render",
         "--bundle-dir", str(bundle), "--identity-dir", str(identity),
         "--config-dir", str(config_dir), "--output", str(config)],
        capture_output=True, text=True, timeout=20)
    assert render.returncode == 0, (render.stdout, render.stderr)
    validation = subprocess.run(
        [str(client), "--diagnostic-logs", "--config", str(config),
         "--validate-config", "--json", "--device-online-bundle", str(bundle)],
        capture_output=True, text=True, timeout=20)
    if sys.platform == "darwin":
        # The exact full-wide profile selects Linux capture. A Mac CLI must
        # reject this backend; do not rewrite the profile to manufacture a pass.
        assert validation.returncode != 0 and validation.stdout == ""
        assert validation.stderr.strip() == "Error: config_ingress_selection_invalid", validation.stderr
        config_validation_result = "linux_backend_refused_on_macos"
    else:
        assert sys.platform == "linux", "run full staging proof on Linux"
        assert validation.returncode == 0, (validation.stdout, validation.stderr)
        assert json.loads(validation.stdout) == {
            "schema": "aegis_config_validation_v1", "valid": True}
        staged_config_valid = True
        config_validation_result = "valid"
print(json.dumps({"scope": "actual CLI identity gate before privileged activation", "expected": expected,
                  "passed": True, "installer_functions_sha256": hashlib.sha256("\n".join(functions).encode()).hexdigest(),
                  "staged_config_valid": staged_config_valid, "live_relay_ack_tested": False,
                  "config_validation_result": config_validation_result,
                  "client_sha256": hashlib.sha256(client.read_bytes()).hexdigest()}))
