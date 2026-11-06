#!/usr/bin/env bash
# Contract: scripts/refresh-chrome-profile.py measures Chrome only in an
# isolated browser. Every launch passes a mock keychain, the basic password
# store and a --user-data-dir inside the system temporary directory, so a run
# on a developer Mac neither prompts for nor reads the login keychain, and no
# real browser profile is opened. An earlier run without these flags raised a
# macOS keychain prompt on the owner's Mac.
#
# No browser is started: subprocess.Popen is replaced by a recorder.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

python3 -I - "${ROOT}/scripts/refresh-chrome-profile.py" <<'PY'
import importlib.util
import os
import sys
import tempfile
from pathlib import Path

script = Path(sys.argv[1])
spec = importlib.util.spec_from_file_location("refresh_chrome_profile", script)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

launched = []


class Recorder:
    def __init__(self, args, **_kwargs):
        launched.append(list(args))

    def wait(self, timeout=None):
        return 0

    def kill(self):
        pass


module.subprocess.Popen = Recorder

failures = []
with tempfile.TemporaryDirectory(prefix="aegis-refresh-contract-") as tmp:
    for quic in (None, 4433):
        module.launch_chrome("/nonexistent/chrome", tmp + "/run", "https://127.0.0.1:1/", quic)
    for outside in (str(Path.home() / "Library/Application Support/Google/Chrome"), ""):
        try:
            module.launch_chrome("/nonexistent/chrome", outside, "https://127.0.0.1:1/", None)
        except Exception:
            continue
        failures.append(f"launch accepted a user-data-dir outside the temp dir: {outside!r}")

temp_root = Path(tempfile.gettempdir()).resolve()
if len(launched) != 2:
    failures.append(f"expected 2 recorded launches, got {len(launched)}")
for args in launched:
    for flag in ("--use-mock-keychain", "--password-store=basic", "--headless=new"):
        if flag not in args:
            failures.append(f"{flag} missing from {args}")
    dirs = [a.split("=", 1)[1] for a in args if a.startswith("--user-data-dir=")]
    if len(dirs) != 1:
        failures.append(f"expected one --user-data-dir in {args}")
    elif not Path(dirs[0]).resolve().is_relative_to(temp_root):
        failures.append(f"user-data-dir {dirs[0]} is outside {temp_root}")
    if args[-1] != "https://127.0.0.1:1/":
        failures.append(f"URL is not the last argument: {args}")

source = script.read_text()
for needle in (
    "Library/Application Support/Google",
    ".config/google-chrome",
    "find-generic-password",
    "Login Data",
    "Cookies",
):
    if needle in source:
        failures.append(f"refresh script references {needle!r}")
if 'tempfile.TemporaryDirectory(prefix="aegis-chrome-profile-")' not in source:
    failures.append("main() no longer measures under a TemporaryDirectory")

if failures:
    for failure in failures:
        print("FAIL:", failure)
    sys.exit(1)
print("chrome profile refresh isolation contract: ok")
PY

# The weekly workflow lives in a public repository. It must not run for
# forks or pushes, must not read secrets, and the token that can push or open
# a pull request must never be in a job that installs Chrome, builds crates or
# runs Python: a dependency or the browser package could read it from the
# runner. Any write token lives in a job that only runs git and gh.
python3 -I - "${ROOT}/.github/workflows/chrome-profile-refresh.yml" <<'PY'
import re
import sys
from pathlib import Path

lines = Path(sys.argv[1]).read_text().splitlines()
failures = []


def block(start_pattern, indent):
    """Lines under the first line matching start_pattern, until dedent."""
    for index, line in enumerate(lines):
        if re.match(start_pattern, line):
            out = []
            for item in lines[index + 1 :]:
                if item.strip() and (len(item) - len(item.lstrip())) < indent:
                    break
                out.append(item)
            return out
    return None


on = block(r"^on:\s*$", 2)
if on is None:
    failures.append("no `on:` block")
else:
    triggers = {m.group(1) for m in (re.match(r"^  ([a-z_]+):", l) for l in on) if m}
    if not triggers or not triggers <= {"schedule", "workflow_dispatch"}:
        failures.append(f"triggers must be schedule/workflow_dispatch only, got {sorted(triggers)}")

text = "\n".join(l for l in lines if not l.lstrip().startswith("#"))
if re.search(r"(?m)^\s*(pull_request|pull_request_target|push|workflow_run)\s*:", text):
    failures.append("a push, pull_request, pull_request_target or workflow_run trigger appears")
if re.search(r"\$\{\{\s*secrets\.", text):
    failures.append("the workflow references repository secrets")
for match in re.finditer(r"uses:\s*([^\s#]+)", text):
    if not re.search(r"@[0-9a-f]{40}$", match.group(1)):
        failures.append(f"action not pinned to a commit: {match.group(1)}")

jobs_index = next((i for i, l in enumerate(lines) if l == "jobs:"), None)
if jobs_index is None:
    failures.append("no jobs")
    jobs = {}
else:
    top = "\n".join(l for l in lines[:jobs_index] if not l.lstrip().startswith("#"))
    if "write" in top or not re.search(r"(?m)^permissions:\s*(\{\}|read-all)\s*$", top):
        failures.append("top-level permissions must be `{}` or `read-all`")
    jobs = {}
    current = None
    for line in lines[jobs_index + 1 :]:
        header = re.match(r"^  ([A-Za-z0-9_-]+):\s*$", line)
        if header:
            current = header.group(1)
            jobs[current] = []
        elif current:
            jobs[current].append(line)

builds = re.compile(r"\b(cargo|apt-get|python3|wget|curl|pip|npm|make)\b")
for name, body in jobs.items():
    job = "\n".join(body)
    writes = re.findall(r"(?m)^\s+([a-z-]+):\s*write\s*$", job)
    if not re.search(r"(?m)^    permissions:\s*$", job):
        failures.append(f"job {name} does not declare its own permissions")
    runs_code = bool(builds.search(job))
    if runs_code and writes:
        failures.append(f"job {name} runs third-party code with write scopes {writes}")
    if runs_code and "persist-credentials: false" not in job:
        failures.append(f"job {name} runs third-party code with a persisted checkout token")
    if writes and not re.search(r"(?m)^    needs:", job):
        failures.append(f"write job {name} does not depend on a read-only job")

if not any(re.search(r"(?m)^\s+contents:\s*write\s*$", "\n".join(b)) for b in jobs.values()):
    failures.append("no job can push the refresh branch")

if failures:
    for failure in failures:
        print("FAIL:", failure)
    sys.exit(1)
print("chrome profile refresh workflow contract: ok")
PY
