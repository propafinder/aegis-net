#!/usr/bin/env bash
# Inert regression: detailed helper logs require explicit opt-in before launch.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
python3 - "${ROOT}" <<'PY'
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

root = Path(sys.argv[1])
helper = root / "scripts/setup-wide-linux-tproxy.sh"
source = helper.read_text()
guard = re.search(r'^DIAGNOSTIC_LOGS=.*?^fi$', source, re.M | re.S).group()
builder = re.search(r'^build_launch_command\(\) \{.*?^\}', source, re.M | re.S).group()
setup = '''set -eu
resolve_client_exec_prefix() { CLIENT_EXEC_PREFIX=(/owned/aegis-client); }
CLIENT_CONFIG=/owned/synthetic.toml
ENABLE_RUNTIME_EVENTS_JSONL=1
RUNTIME_EVENTS_JSONL=/owned/synthetic.jsonl
'''
for setting, enabled in ((None, False), ("0", False), ("1", True)):
    env = dict(os.environ)
    env.pop("AEGIS_DIAGNOSTIC_LOGS", None)
    if setting is not None:
        env["AEGIS_DIAGNOSTIC_LOGS"] = setting
    result = subprocess.run(["bash"], input=setup + guard + "\n" + builder +
                            '\nbuild_launch_command\nprintf "%s\\0" "${LAUNCH_CMD[@]}"\n',
                            env=env, text=True, capture_output=True, timeout=10)
    assert result.returncode == 0, result.stderr
    expected = ["/owned/aegis-client", "--config", "/owned/synthetic.toml"]
    if enabled:
        expected.append("--diagnostic-logs")
    expected += ["--runtime-events-jsonl", "/owned/synthetic.jsonl", ""]
    assert result.stdout.split("\0") == expected, result.stdout

# Run the actual entrypoint: malformed values must stop before root-state,
# host probing, launch or any firewall operation (even for action=apply).
with tempfile.TemporaryDirectory(prefix="aegis-diagnostics-contract-") as directory:
    marker = Path(directory) / "unexpected-command"
    for setting in ("", "true", "2", "1 --forensic-safe", "$(touch " + str(marker) + ")"):
        env = dict(os.environ, AEGIS_DIAGNOSTIC_LOGS=setting,
                   AEGIS_CLIENT_CONFIG="", AEGIS_RUNTIME_EVENTS_JSONL="/unused")
        result = subprocess.run(["bash", str(helper), "apply"], env=env,
                                text=True, capture_output=True, timeout=10)
        assert result.returncode == 2, (setting, result.stderr)
        assert result.stderr.strip() == "AEGIS_DIAGNOSTIC_LOGS must be 0 or 1", result.stderr
        assert not marker.exists(), "diagnostic value was executed"

smoke = (root / "scripts/smoke-wide-linux-tproxy.sh").read_text()
assert re.search(r'AEGIS_CLIENT_CONFIG="\$\{CFG_PATH\}" \\\n  AEGIS_DIAGNOSTIC_LOGS=1 .*?setup-wide-linux-tproxy\.sh" launch', smoke, re.S)
redirect = (root / "scripts/smoke-wide-linux-redirect.sh").read_text()
assert 'cargo run -p aegis-client -- --config "${CFG_PATH}" --diagnostic-logs >"${CLIENT_LOG}"' in redirect
print("TPROXY diagnostics: default/zero private, explicit one, five invalid entrypoints, smoke opt-ins PASS (inert)")
PY
