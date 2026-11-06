#!/usr/bin/env python3
"""Exercise the actual V2 shell prefix with inert planner and capture actors."""

from pathlib import Path
import os
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parent.parent
source = (ROOT / "install.sh").read_text()
match = re.search(r'^install_client_auto_v2\(\) \(\n.*?^\)', source, re.M | re.S)
assert match, "actual V2 installer function absent"
prefix, marker = match[0].split("  python3 -I -B - <<'PY_AUTO_PASSIVE'", 1)
assert marker, "fresh passive actor boundary absent"
# Root and Linux are fixture facts only; all real mutation commands are stubs.
prefix = prefix.replace('"$EUID" == 0', '"0" == 0', 1)
helper = re.search(r'^auto_v2_selected_plan\(\) \{\n.*?^\}', source, re.M | re.S)
actual = (helper[0] + '\n' if helper else '') + prefix + '  record passive-actor-start; return 0\n  fi\n)\n'

with tempfile.TemporaryDirectory(prefix="aegis-auto-v2-early-plan-") as temporary:
    work = Path(temporary)
    bundle = work / "bundle"
    bundle.mkdir()
    (bundle / "aegis-client.toml").write_text("inert config; fake client never reads it\n")
    candidate = work / "client"
    candidate.write_text('''#!/usr/bin/env bash
printf '%s\\n' "$*" >> "$FIXTURE_CALLS"
if [[ "$1 $2 $3" == 'profile auto-config protocol' ]]; then
  echo auto-config-snapshot-v2; exit 0
fi
if [[ "$1 $2" == 'profile auto' ]]; then
  [[ "$PLAN_RESULT" == planned ]] || exit 74
  printf '{"schema":"aegis_auto_install_plan_v1","status":"planned","product_mode":"%s","connectivity_verified":false}\\n' "$PLAN_MODE"
  exit 0
fi
exit 98
''')
    candidate.chmod(0o755)
    stubs = '''
record() { printf '%s\\n' "$1" >> "$FIXTURE_EVENTS"; }
detect_os_kind() { echo linux; }
systemd_activation_requested() { return 0; }
install_root_auto_native_role() { AUTO_NATIVE_ROLE=admin; }
require_asset() { :; }
auto_v2_passive_receipt() {
  record passive-intent
  AUTO_V2_PASSIVE_BUNDLE="$BUNDLE_PATH"
  AUTO_V2_PASSIVE_STATUS=fresh
}
preflight_wide_capture() {
  record "capture:$1"
  [[ "$CAPTURE_REFUSE" != 1 ]]
}
'''
    script = work / "fixture.sh"
    script.write_text('set -euo pipefail\n' + stubs + actual + '''
install_client_auto_v2 /usr/local /etc/aegis/client /var/lib/aegis-client /var/log/aegis-client /var/log/aegis-client/events.jsonl none
''')
    for case, plan, mode, capture_refuse, device_required, expected_code, expected_event in (
        ("planner-refusal", "blocked", "full-wide-tun", "0", "0", False, None),
        ("capture-refusal", "planned", "full-wide-tun", "1", "0", False, "capture:client-ipv6-tun-smoltcp"),
        ("device-downgrade", "planned", "socks-only", "0", "1", False, None),
        ("socks-control", "planned", "socks-only", "1", "0", True, None),
    ):
        events = work / f"{case}.events"
        calls = work / f"{case}.calls"
        env = dict(os.environ, ROOT=str(work), PREFLIGHT_CLIENT_BINARY=str(candidate),
                   BUNDLE_PATH=str(bundle), AUTO_FRESH_PACKAGE="1",
                   AUTO_FRESH_PACKAGE_ROOT=str(work), STAGE_AUTO_INSTALL_LOCK_FD="9",
                   AUTO_V2_PASSIVE_ORIGIN="source-layout", AUTO_V2_REQUESTED_MODE="",
                   CLIENT_PACKAGE="", SYSTEMD_DIR="/etc/systemd/system", ENV_DIR="/etc/default",
                   PLAN_RESULT=plan, PLAN_MODE=mode, CAPTURE_REFUSE=capture_refuse,
                   AUTO_DEVICE_V2_REQUIRED=device_required,
                   FIXTURE_EVENTS=str(events), FIXTURE_CALLS=str(calls))
        result = subprocess.run(["/bin/bash", str(script)], env=env, capture_output=True, text=True, timeout=5)
        recorded = events.read_text().splitlines() if events.exists() else []
        invoked = calls.read_text().splitlines() if calls.exists() else []
        assert (result.returncode == 0) == expected_code, (case, result.returncode, result.stderr, recorded)
        assert any(line.startswith("profile auto --config ") for line in invoked), (case, invoked)
        assert recorded[0] == "passive-intent", (case, recorded)
        if expected_event:
            assert expected_event in recorded, (case, recorded)
        else:
            assert not any(x.startswith("capture:") for x in recorded), (case, recorded)
        assert ("passive-actor-start" in recorded) == expected_code, (case, recorded)

print("PASS: held V2 input is planned before passive actors; planner/capture refusals leave them untouched")
