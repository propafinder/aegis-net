#!/usr/bin/env bash
# Exercise the actual integrity/advisory entry point against isolated local
# copies. Cargo is a recording fixture: no Rust build, advisory fetch or network.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
python3 -I - "$ROOT" "${AEGIS_VENDORED_AUDIT_SCRIPT:-$ROOT/scripts/audit-vendored-dependencies.sh}" <<'PY'
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

root, candidate = map(Path, sys.argv[1:])
# A local ignored upstream file must not make this contract greener than a
# fresh Actions checkout. Check the Git inventory before copying fixtures.
record = json.loads((root / "third_party/h2/UPSTREAM.json").read_text())
expected = (set(record["upstream_files_sha256"]) |
            set(record["local_metadata_sha256"]) |
            {item["patch_file"] for item in record["local_patches"].values()} |
            {"UPSTREAM.json"})
inventory = subprocess.run(["git", "ls-files", "-z", "--", "third_party/h2"],
                           cwd=root, capture_output=True, text=True,
                           check=True, timeout=15)
tracked = {name.removeprefix("third_party/h2/")
           for name in inventory.stdout.split("\0") if name}
if tracked != expected:
    raise SystemExit("vendored Git inventory differs from provenance: " +
                     ", ".join(sorted(tracked ^ expected)))
results = []
with tempfile.TemporaryDirectory(prefix="aegis-vendored-integrity-") as temporary:
    work = Path(temporary)
    tools = work / "tools"
    tools.mkdir()
    cargo = tools / "cargo"
    cargo.write_text("#!" + sys.executable + " -I\n" + '''
import json, os, pathlib, sys
fixture = pathlib.Path(os.environ["AEGIS_VENDOR_FIXTURE_ROOT"])
if sys.argv[1:] == ["metadata", "--locked", "--format-version", "1"]:
    print(json.dumps({"packages": [{"name": "h2", "version": "0.4.16", "source": None,
          "manifest_path": str(fixture / "third_party/h2/Cargo.toml")}]}))
elif len(sys.argv) >= 3 and sys.argv[1] == "audit":
    assert sys.argv[2] == "--file" and "--deny" in sys.argv and "warnings" in sys.argv and "--no-yanked" in sys.argv
    lock = pathlib.Path(sys.argv[3]).read_text()
    assert 'name = "h2"' in lock and 'version = "0.4.16"' in lock
    assert 'source = "registry+https://github.com/rust-lang/crates.io-index"' in lock
    (fixture / "advisory-invoked").write_text("fixture advisory invoked\\n")
    sys.exit(int(os.environ.get("AEGIS_VENDOR_FIXTURE_AUDIT_STATUS", "0")))
else:
    raise SystemExit("unexpected Cargo invocation")
''')
    cargo.chmod(0o755)

    cases = (
        ("intentional-patch", "accept"),
        ("tampered-upstream-file", "reject"),
        ("tampered-patched-file", "reject"),
        ("tampered-patched-lock", "reject"),
        ("tampered-lock-patch-artifact", "reject"),
        ("unrecorded-source-file", "reject"),
        ("missing-upstream-file", "reject"),
        ("missing-patch-metadata", "reject"),
        ("missing-patch-artifact", "reject"),
        ("missing-patch-documentation", "reject"),
        ("patched-source-relabelled-upstream", "reject"),
        ("tampered-patch-artifact", "reject"),
        ("symlink-upstream-file", "reject"),
        ("symlink-provenance", "reject"),
        ("advisory-failure", "advisory-reject"),
    )
    for index, (name, expected) in enumerate(cases):
        fixture = work / str(index)
        (fixture / "scripts").mkdir(parents=True)
        shutil.copy2(candidate, fixture / "scripts/audit-vendored-dependencies.sh")
        vendor = fixture / "third_party/h2"
        shutil.copytree(root / "third_party/h2", vendor)
        provenance = vendor / "UPSTREAM.json"
        record = json.loads(provenance.read_text())
        env = {**os.environ, "PATH": str(tools) + os.pathsep + os.environ["PATH"],
               "AEGIS_VENDOR_FIXTURE_ROOT": str(fixture), "AEGIS_CARGO_AUDIT_DB": "",
               "AEGIS_VENDOR_FIXTURE_AUDIT_STATUS": "7" if name == "advisory-failure" else "0"}
        if name == "tampered-upstream-file":
            with (vendor / "src/client.rs").open("a") as stream:
                stream.write("\n// harmless integrity regression fixture\n")
        elif name == "tampered-patched-file":
            with (vendor / "src/frame/headers.rs").open("a") as stream:
                stream.write("\n// harmless patch integrity regression fixture\n")
        elif name == "tampered-patched-lock":
            with (vendor / "Cargo.lock").open("a") as stream:
                stream.write("\n# harmless lock integrity regression fixture\n")
        elif name == "tampered-lock-patch-artifact":
            with (vendor / "AEGIS-LOCK-PATCH.diff").open("a") as stream:
                stream.write("\n")
        elif name == "unrecorded-source-file":
            (vendor / "src/unrecorded-fixture.rs").write_text("// harmless fixture\n")
        elif name == "missing-upstream-file":
            (vendor / "src/client.rs").unlink()
        elif name == "missing-patch-metadata":
            record.pop("local_patches", None)
            provenance.write_text(json.dumps(record))
        elif name == "missing-patch-artifact":
            (vendor / "AEGIS-PATCH.diff").unlink()
        elif name == "missing-patch-documentation":
            (vendor / "AEGIS-PATCH.md").unlink()
        elif name == "patched-source-relabelled-upstream":
            record["upstream_files_sha256"]["src/frame/headers.rs"] = hashlib.sha256(
                (vendor / "src/frame/headers.rs").read_bytes()).hexdigest()
            provenance.write_text(json.dumps(record))
        elif name == "tampered-patch-artifact":
            with (vendor / "AEGIS-PATCH.diff").open("a") as stream:
                stream.write("\n")
        elif name == "symlink-upstream-file":
            source = vendor / "src/client.rs"
            outside = fixture / "outside-client.rs"
            source.rename(outside)
            source.symlink_to(outside)
        elif name == "symlink-provenance":
            outside = fixture / "outside-UPSTREAM.json"
            provenance.rename(outside)
            provenance.symlink_to(outside)
        run = subprocess.run(["bash", str(fixture / "scripts/audit-vendored-dependencies.sh")],
                             cwd=fixture, env=env, capture_output=True, text=True, timeout=15)
        advisory = (fixture / "advisory-invoked").exists()
        passed = ((run.returncode == 0 and advisory) if expected == "accept" else
                  (run.returncode != 0 and advisory) if expected == "advisory-reject" else
                  (run.returncode != 0 and not advisory))
        results.append({"case": name, "expected": expected, "exit_code": run.returncode,
                        "advisory_invoked": advisory, "passed": passed,
                        "output": (run.stdout + run.stderr).strip()})
print(json.dumps({"cases": results, "network": "none; recording Cargo fixture"}, indent=2))
if not all(case["passed"] for case in results):
    raise SystemExit(1)
print(f"vendored integrity contract: PASS ({len(cases)} isolated cases; advisory step retained)")
PY
