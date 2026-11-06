"""Record the h2 per-stream receive-window delta's custody in a vendored tree.

usage: python3 -I record_window_delta.py <h2 dir> <upstream source dir>

<upstream source dir> holds the three files exactly as recorded in
UPSTREAM.json upstream_files_sha256. Writes AEGIS-WINDOW-PATCH-{1,2,3}.diff
(zero-context single-file diffs, the format AEGIS-PATCH.diff uses) and
appends their custody to UPSTREAM.json, refreshing the AEGIS-PATCH.md hash.
Existing keys and their order are preserved; nothing else is touched.
"""
import hashlib
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path

FILES = [
    ("src/share.rs", "AEGIS-WINDOW-PATCH-1.diff"),
    ("src/proto/streams/streams.rs", "AEGIS-WINDOW-PATCH-2.diff"),
    ("src/proto/streams/recv.rs", "AEGIS-WINDOW-PATCH-3.diff"),
]


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def zero_context_diff(relative: str, upstream: bytes, patched: bytes) -> bytes:
    with tempfile.TemporaryDirectory() as tmp:
        a, b = Path(tmp, "a"), Path(tmp, "b")
        a.write_bytes(upstream)
        b.write_bytes(patched)
        run = subprocess.run(
            ["git", "diff", "--no-index", "--no-color", "-U0", "--", str(a), str(b)],
            capture_output=True, timeout=30)
        if run.returncode not in (0, 1):
            raise SystemExit(run.stderr.decode())
    lines = run.stdout.decode("utf-8").splitlines(keepends=True)
    start = next(i for i, line in enumerate(lines) if line.startswith("@@ "))
    hunks = [re.sub(r"^(@@ -\d+(?:,\d+)? \+\d+(?:,\d+)? @@).*\n$", r"\1\n", line)
             if line.startswith("@@ ") else line for line in lines[start:]]
    for line in hunks:
        if line.startswith("\\"):
            raise SystemExit(f"missing final newline in {relative}")
    return "".join([f"--- a/{relative}\n", f"+++ b/{relative}\n", *hunks]).encode("utf-8")


def main() -> None:
    root, upstream_dir = Path(sys.argv[1]), Path(sys.argv[2])
    provenance = root / "UPSTREAM.json"
    raw = provenance.read_text()
    record = json.loads(raw)
    if json.dumps(record, indent=2) + "\n" != raw:
        raise SystemExit("UPSTREAM.json is not in the expected json.dumps(indent=2) form")
    for relative, patch_file in FILES:
        upstream = (upstream_dir / relative).read_bytes()
        if sha(upstream) != record["upstream_files_sha256"][relative]:
            raise SystemExit(f"upstream copy differs from the recorded hash: {relative}")
        patched = (root / relative).read_bytes()
        delta = zero_context_diff(relative, upstream, patched)
        if any(line.startswith(b"-") and not line.startswith(b"--- ")
               for line in delta.splitlines()):
            raise SystemExit(f"the delta removes upstream lines: {relative}")
        (root / patch_file).write_bytes(delta)
        if relative not in record["local_modifications"]:
            record["local_modifications"].append(relative)
        record["local_patches"][relative] = {
            "patched_sha256": sha(patched),
            "patch_file": patch_file,
            "patch_sha256": sha(delta),
            "documentation": "AEGIS-PATCH.md",
        }
        print(f"{relative}: upstream {sha(upstream)} patched {sha(patched)} "
              f"{patch_file} {sha(delta)}")
    record["local_metadata_sha256"]["AEGIS-PATCH.md"] = sha((root / "AEGIS-PATCH.md").read_bytes())
    print(f"AEGIS-PATCH.md {record['local_metadata_sha256']['AEGIS-PATCH.md']}")
    provenance.write_text(json.dumps(record, indent=2) + "\n")


main()
