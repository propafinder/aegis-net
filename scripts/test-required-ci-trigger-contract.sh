#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORKFLOW="${ROOT}/.github/workflows/ci.yml"

[[ -f "${WORKFLOW}" ]] || {
  echo "FAIL: required CI workflow is missing" >&2
  exit 1
}

grep -Eq '^[[:space:]]+push:' "${WORKFLOW}" || {
  echo "FAIL: required CI must run on protected-main pushes" >&2
  exit 1
}
grep -Eq '^[[:space:]]+pull_request:' "${WORKFLOW}" || {
  echo "FAIL: required CI must run on pull requests" >&2
  exit 1
}

if grep -Eq '^[[:space:]]+paths-ignore:' "${WORKFLOW}"; then
  echo "FAIL: paths-ignore suppresses required check contexts and deadlocks protected docs-only PRs" >&2
  exit 1
fi

for context in rust linux-arm64 darwin-contract windows-rust; do
  grep -Eq "^[[:space:]]{2}${context}:" "${WORKFLOW}" || {
    echo "FAIL: protected-main check context job is missing: ${context}" >&2
    exit 1
  }
done

python3 - "${ROOT}" <<'PY'
import os
import re
import subprocess
import sys
import tempfile
import textwrap
from pathlib import Path

root = Path(sys.argv[1])
workflow = (root / ".github/workflows/ci.yml").read_text(encoding="utf-8")
timeout_branch = re.compile(
    r'^          if \[\[ "\$\{status\}" -eq 124 \]\]; then\n'
    r'(?P<body>(?:^            [^\n]*\n)+)^          fi$',
    re.MULTILINE,
)
branches = list(timeout_branch.finditer(workflow))
smoke_calls = re.findall(r'^\s+timeout \d+ bash scripts/smoke-wide-linux-tproxy\.sh$', workflow, re.MULTILINE)
assert len(branches) == len(smoke_calls) == 8, "every guarded smoke must expose a timeout branch"
helper = root / "scripts/lib/guarded-smoke-status.sh"

with tempfile.TemporaryDirectory(prefix="aegis-guarded-timeout-") as temp:
    env = {"PATH": os.environ["PATH"], "RUNNER_TEMP": temp}
    for index, match in enumerate(branches):
        # Only the real status/diagnostic/exit branch runs. Never execute its
        # surrounding capability probes, smoke command, sudo or networking.
        body = [line.strip() for line in match["body"].splitlines()]
        assert len(body) == 3, "timeout branch must remain status, diagnostic and exit only"
        assert body[0].startswith('guarded_smoke_status_write "failed:124'), body
        assert body[1].startswith('echo "') and body[1].endswith('" >&2'), body
        assert body[2] == 'exit "${status}"', body
        branch = textwrap.dedent(match[0])
        name = f"timeout-{index}"
        script = (
            'set -euo pipefail\n. "$1"\nguarded_smoke_status_init "$2"\n'
            'status=124\n' + branch + '\nprintf "unexpected fallthrough\\n"\n'
        )
        result = subprocess.run(
            ["bash", "-c", script, "guarded-timeout-contract", str(helper), name],
            env=env, capture_output=True, text=True, timeout=5,
        )
        assert result.returncode == 124, (index, result.returncode, result.stderr)
        recorded = (Path(temp) / "aegis-guarded-smoke-status" / f"{name}.txt").read_text()
        assert recorded == "failed:124\n", recorded
        assert "unexpected fallthrough" not in result.stdout, result.stdout

    # Preserve the existing status-helper representation. A capability skip is
    # still a skip, never evidence that the guarded runtime test passed.
    for name, status in (
        ("passed", "passed"),
        ("capability-missing", "skipped: xt_TPROXY support is unavailable on this runner"),
    ):
        result = subprocess.run(
            ["bash", "-c", 'set -eu; . "$1"; guarded_smoke_status_init "$2"; guarded_smoke_status_write "$3"',
             "guarded-status-contract", str(helper), name, status],
            env=env, capture_output=True, text=True, timeout=5,
        )
        assert result.returncode == 0, result.stderr
        recorded = (Path(temp) / "aegis-guarded-smoke-status" / f"{name}.txt").read_text()
        assert recorded == status + "\n", recorded

skip_reasons = set(re.findall(r'guarded_smoke_status_write "skipped: ([^"]+)"', workflow))
assert skip_reasons == {
    "xt_TPROXY support is unavailable on this runner",
    "nft TPROXY support is unavailable on this runner",
    "ip6tables TPROXY support is unavailable on this runner",
    "IPv6 loopback is unavailable on this runner",
}, skip_reasons
print("PASS: all 8 guarded timeout branches fail with 124; capability skips remain explicit")
PY

echo "PASS: required CI triggers every PR/main push and exposes all protected contexts"
