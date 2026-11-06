#!/usr/bin/env bash
# Execute remaining actual Python helper stages with harmless import traps.
# Bootstrap's downloader remains Python; private acquisition now uses Rust.
# Only local file://, staged archives and temporary directories are used.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
python3 -I - "${ROOT}" <<'PY'
import gzip
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

root = Path(sys.argv[1])
results = []
unsafe_calls = []
leaf_pins = {}
for name in ("bootstrap-install.sh",):
    source = (root / name).read_text()
    helper = re.search(r'^download_url\(\) \{\n.*?^\}', source, re.M | re.S)[0]
    for location in ("cwd", "pythonpath"):
        for phase, module in (("parent", "shutil.py"), ("child", "http/__init__.py")):
            with tempfile.TemporaryDirectory(prefix="aegis-python-isolation-") as temporary:
                work = Path(temporary)
                tools = work / "tools"
                tools.mkdir()
                (tools / "python3").symlink_to(sys.executable)
                hostile = work / "untrusted-imports"
                hostile.mkdir()
                neutral = work / "neutral-cwd"
                neutral.mkdir()
                marker = work / "unexpected-import"
                trap = hostile / module
                trap.parent.mkdir(parents=True, exist_ok=True)
                # A harmless write proves execution; abort before any transfer.
                trap.write_text(
                    "import os\n"
                    f"fd = os.open({str(marker)!r}, os.O_WRONLY | os.O_CREAT, 0o600)\n"
                    "os.write(fd, b'fixture import executed')\nos.close(fd)\n"
                    "raise RuntimeError('synthetic import trap')\n"
                )
                payload = work / "source payload.bin"
                payload.write_bytes(b"local complete fixture")
                destination = work / "copied payload.bin"
                env = {**os.environ, "PATH": str(tools), "OFFLINE": "1",
                       "PYTHONPATH": str(hostile) if location == "pythonpath" else "",
                       "AEGIS_DOWNLOAD_CONNECT_TIMEOUT_SECONDS": "1",
                       "AEGIS_DOWNLOAD_TOTAL_TIMEOUT_SECONDS": "5",
                       "BUNDLE_CACERT_PIN": "", "BUNDLE_INSECURE": "0"}
                result = subprocess.run(
                    ["/bin/bash", "-c", helper + '\ndownload_url "$1" "$2"\n',
                     "isolation-contract", payload.as_uri(), str(destination)],
                    cwd=hostile if location == "cwd" else neutral,
                    env=env, capture_output=True, timeout=10,
                )
                success = (result.returncode == 0 and not marker.exists()
                           and destination.is_file()
                           and destination.read_bytes() == payload.read_bytes())
                results.append({"source": name, "phase": phase, "location": location,
                                "passed": success, "import_executed": marker.exists(),
                                "exit_code": result.returncode})
    # Check every real -/ -c invocation, not dependency-presence checks.
    for match in re.finditer(r'\bpython3[ \t]+(-[^\n]*)', source):
        if not match.group(1).startswith("-I "):
            unsafe_calls.append({"source": name,
                                 "line": source.count("\n", 0, match.start()) + 1})
    if '[sys.executable, "-I", "-c", code,' not in helper:
        unsafe_calls.append({"source": name, "class": "nested_download_interpreter"})

# The private downloader's old Python child no longer exists. Exercise the
# remaining archive-validation and bundle-discovery Python commands from the
# actual resolver, without simulating its Rust verifier or transfer.
name = "install.sh"
source = (root / name).read_text()
resolver = re.search(r'^resolve_downloaded_bundle\(\) \{\n.*?^\}', source, re.M | re.S)[0]
archive = re.search(
    r'^  if ! (python3(?: -I)? - "\$\{archive_path\}" <<\'PY\'\n.*?\nPY)\n  then\n',
    resolver, re.M | re.S,
)[1]
discovery_start = resolver.index("  local py_find_bundle=''")
discovery = resolver[discovery_start:resolver.rindex("\n}")]
archive_leaf = 'stage() {\n  local archive_path="$1"\n' + archive + '\n}\nstage "$1"\n'
discovery_leaf = (
    'stage() {\n  local extracted_root="$1" output_var=found nested_dir=""\n'
    + discovery + '\n}\nfound=""\nstage "$1" || exit "$?"\nprintf "%s" "$found"\n'
)
leaf_pins["install_archive_python_command"] = hashlib.sha256(archive.encode()).hexdigest()
leaf_pins["install_discovery_actual_tail"] = hashlib.sha256(discovery.encode()).hexdigest()
for location in ("cwd", "pythonpath"):
    for phase, module, leaf in (("archive_validation", "gzip.py", archive_leaf),
                                ("bundle_discovery", "pathlib.py", discovery_leaf)):
        with tempfile.TemporaryDirectory(prefix="aegis-python-isolation-") as temporary:
            work = Path(temporary)
            tools = work / "tools"
            tools.mkdir()
            (tools / "python3").symlink_to(sys.executable)
            hostile = work / "untrusted-imports"
            hostile.mkdir()
            neutral = work / "neutral-cwd"
            neutral.mkdir()
            marker = work / "unexpected-import"
            trap = hostile / module
            trap.write_text(
                "import os\n"
                f"fd = os.open({str(marker)!r}, os.O_WRONLY | os.O_CREAT, 0o600)\n"
                "os.write(fd, b'fixture import executed')\nos.close(fd)\n"
                "raise RuntimeError('synthetic import trap')\n"
            )
            payload = b"local complete fixture"
            if phase == "archive_validation":
                input_path = work / "complete archive.gz"
                expected_bytes = gzip.compress(payload, mtime=0)
                input_path.write_bytes(expected_bytes)
                expected_output = b""
            else:
                input_path = work / "staged archive"
                bundle = input_path / "nested bundle"
                bundle.mkdir(parents=True)
                (bundle / "aegis-client.toml").write_bytes(payload)
                (bundle / "ca.pem").write_bytes(b"inert public certificate fixture")
                expected_output = str(bundle).encode()
            env = {**os.environ, "PATH": str(tools),
                   "PYTHONPATH": str(hostile) if location == "pythonpath" else ""}
            result = subprocess.run(
                ["/bin/bash", "-c", leaf, "isolation-contract", str(input_path)],
                cwd=hostile if location == "cwd" else neutral,
                env=env, capture_output=True, timeout=10,
            )
            if phase == "archive_validation":
                data_complete = (input_path.read_bytes() == expected_bytes
                                 and gzip.decompress(input_path.read_bytes()) == payload)
            else:
                data_complete = ((bundle / "aegis-client.toml").read_bytes() == payload
                                 and (bundle / "ca.pem").is_file())
            success = (result.returncode == 0 and not marker.exists()
                       and result.stdout == expected_output and data_complete)
            results.append({"source": name, "phase": phase, "location": location,
                            "passed": success, "import_executed": marker.exists(),
                            "exit_code": result.returncode, "data_complete": data_complete})

# Retain the original inventory policy for every real remaining -/-c call.
for match in re.finditer(r'\bpython3[ \t]+(-[^\n]*)', source):
    if not match.group(1).startswith("-I "):
        unsafe_calls.append({"source": name,
                             "line": source.count("\n", 0, match.start()) + 1})

print(json.dumps({"cases": results, "unisolated_calls": unsafe_calls,
                  "actual_leaf_sha256": leaf_pins}, sort_keys=True))
if unsafe_calls or not all(case["passed"] for case in results):
    raise SystemExit(1)
print("installer-python-isolation-contract: PASS (8 actual Python stages; local fixtures only)")
PY
