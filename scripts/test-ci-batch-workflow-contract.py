#!/usr/bin/env python3
"""Require the full-matrix dispatch and exact reviewed h2 custody in CI."""
import json
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

root = Path(__file__).resolve().parents[1]
workflow = (root / ".github/workflows/ci.yml").read_text()
rust = workflow.split("\n  rust:\n", 1)[1].split("\n  native-generation-seal:\n", 1)[0]
checkout = rust.split("      - name: Checkout\n", 1)[1].split("      - name:", 1)[0]
assert "fetch-depth: 0" in checkout
assert "python3 -I -B -m unittest discover -s scripts/tests -p 'test_b114_hosted_product_binding.py' -q" in rust
darwin = workflow.split("\n  darwin-contract:\n", 1)[1].split("\n  windows-rust:\n", 1)[0]
assert re.search(r"^    timeout-minutes: 240$", darwin, re.M)
native = darwin.split("      - name: Darwin standalone NetworkExtension native source and library tests\n", 1)[1].split("      - name:", 1)[0]
assert "timeout-minutes: 45" in native
assert "test_assemble_observe_staging.py" not in native
assert 'policy_execution="${RUNNER_TEMP}/aegis-darwin-policy-${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}"' in native
assert 'test ! -e "$policy_execution"' in native
assert 'mkdir -m 700 "$policy_execution"' in native
assert "python3 -I -B scripts/tests/test_darwin_launchd_exec.py" in native
assert 'scripts/qa/darwin-launchd-exec-r1.py --repo "$PWD" --execution "$policy_execution/launchd" --timeout-seconds 2700' in native
assert "python3 -I -B scripts/tests/test_darwin_test_task_policy_runner.py" in native
assert "python3 -I -B scripts/tests/test_prepare_darwin_test_task_runner.py" in native
assert 'install -m 0600 /dev/null "$policy_execution/cargo-build.jsonl"' in native
assert '--target-root "$target_root"' in native
assert "scripts/qa/prepare-darwin-test-task-runner-r1.py" in native
assert "CARGO_PROFILE_TEST_OPT_LEVEL: '1'" in native.split("        run: |", 1)[0]
assert "CARGO_PROFILE_TEST_DEBUG_ASSERTIONS: 'true'" in native.split("        run: |", 1)[0]
assert "CARGO_PROFILE_TEST_OVERFLOW_CHECKS: 'true'" in native.split("        run: |", 1)[0]
assert '--expected-opt-level 1' in native

assert 'cargo test --locked --manifest-path "$manifest" --target "$host_target" --all-features --lib --no-run --message-format=json > "$policy_execution/cargo-build.jsonl"' in native
assert 'python3 -I -B scripts/qa/darwin-process-foreground-exec-r1.py -- cargo --config "$policy_execution/runner.toml" test --locked --manifest-path "$manifest" --target "$host_target" --all-features --lib -- --test-threads=1' in native
assert native.index("--no-run --message-format=json") < native.index(
    "scripts/qa/prepare-darwin-test-task-runner-r1.py") < native.index(
    'cargo --config "$policy_execution/runner.toml" test')
staging = darwin.split("      - name: Darwin NetworkExtension assembly and observation staging\n", 1)[1].split("      - name:", 1)[0]
assert "timeout-minutes: 120" in staging
assert "set -euo pipefail" in staging
assert '[[ "$host_target" == *-apple-darwin ]]' in staging
assert "MACOSX_DEPLOYMENT_TARGET=14.4" in staging
assert "python3 -I -B tools/macos/aegis-network-extension/tests/test_assemble_observe_staging.py" in staging

windows = workflow.split("\n  windows-rust:\n", 1)[1]
for name in ("Build private Windows release kit", "Verify installed Windows release lifecycle"):
    step = windows.split(f"      - name: {name}\n", 1)[1].split("      - name:", 1)[0]
    assert "github.event_name == 'workflow_dispatch'" in step, name
assert "python3 -I -B scripts/test-ci-batch-workflow-contract.py" in workflow

# Exercise the actual shell block's collection behavior. These inert commands
# test control flow only; they provide no archive/ELF acceptance evidence.
assets = workflow.split(
    "      - name: Verify actual Linux administrative and research archive roles\n", 1
)[1].split("      - name:", 1)[0]
assert "timeout-minutes: 3" in assets
run_lines = assets.split("        run: |\n", 1)[1].splitlines()
body_lines = []
for line in run_lines:
    if line and not line.startswith("          "):
        break
    body_lines.append(line[10:] if line else "")
asset_body = "\n".join(body_lines)
with tempfile.TemporaryDirectory(prefix="aegis-ci-asset-flow-") as temporary:
    fixture = Path(temporary)
    (fixture / "scripts").mkdir()
    paths = (
        "test_admin_research_helper_inventory.py",
        "test-auto-native-install-assets.py",
        "test-device-stage-owner-admission-contract.py",
    )
    for index, name in enumerate(paths, 1):
        (fixture / "scripts" / name).write_text(
            "import os\n"
            "with open(os.environ['AEGIS_CI_CASES_TRACE'], 'a') as trace:\n"
            f"    trace.write('{index}\\n')\n"
            f"raise SystemExit(41 if os.environ['AEGIS_CI_FAIL_INDEX'] == '{index}' else 0)\n"
        )
    (fixture / "scripts/test-admin-research-delivery-split-contract.sh").write_text(
        'test "$#" -eq 2 && test "$1" = --builder-output || exit 42\n'
        'test "$2" = "${RUNNER_TEMP}/installer-source-prebuild-${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}" || exit 43\n'
        'printf "4\\n" >> "${AEGIS_CI_CASES_TRACE}"\n'
        'test "${AEGIS_CI_FAIL_INDEX}" != 4\n'
    )
    failures = []
    for failed_index in range(5):
        trace = fixture / f"trace-{failed_index}.txt"
        result = subprocess.run(
            ["bash", "-e", "-u", "-o", "pipefail", "-c", asset_body],
            cwd=fixture, capture_output=True, text=True, timeout=10,
            env={**os.environ, "AEGIS_CI_CASES_TRACE": str(trace),
                 "AEGIS_CI_FAIL_INDEX": str(failed_index),
                 "RUNNER_TEMP": str(fixture / "runner temporary"),
                 "GITHUB_RUN_ID": "123", "GITHUB_RUN_ATTEMPT": "2"},
            check=False,
        )
        observed = trace.read_text().splitlines() if trace.exists() else []
        if observed != ["1", "2", "3", "4"] or (
            (result.returncode == 0) != (failed_index == 0)
        ):
            failures.append({"failed_index": failed_index, "observed": observed,
                             "returncode": result.returncode,
                             "stderr": result.stderr})
    assert not failures, f"archive contract collection failed: {failures}"

original = json.loads((root / "third_party/h2/UPSTREAM.json").read_text())
expected = ["src/frame/headers.rs", "Cargo.lock", "src/share.rs",
            "src/proto/streams/streams.rs", "src/proto/streams/recv.rs"]
assert original["local_modifications"] == expected
with tempfile.TemporaryDirectory(prefix="aegis-h2-window-") as temporary:
    fixture = Path(temporary)
    (fixture / "scripts").mkdir()
    (fixture / ".github/workflows").mkdir(parents=True)
    (fixture / "third_party/h2").mkdir(parents=True)
    shutil.copyfile(root / "scripts/test-vendored-advisory-coverage-contract.sh",
                    fixture / "scripts/test-vendored-advisory-coverage-contract.sh")
    shutil.copyfile(root / "third_party/h2/Cargo.toml", fixture / "third_party/h2/Cargo.toml")
    (fixture / ".github/workflows/ci.yml").write_text(
        "bash ./scripts/audit-vendored-dependencies.sh\n")
    (fixture / "scripts/audit-vendored-dependencies.sh").write_text(".source == null\n")

    def admitted(metadata):
        (fixture / "third_party/h2/UPSTREAM.json").write_text(json.dumps(metadata))
        return subprocess.run(
            ["bash", str(fixture / "scripts/test-vendored-advisory-coverage-contract.sh")],
            cwd=fixture, capture_output=True, text=True, check=False,
        ).returncode == 0

    assert admitted(original), "reviewed five-file h2 inventory refused"
    old = json.loads(json.dumps(original))
    old["local_modifications"] = old["local_modifications"][:2]
    old["local_patches"] = {k: v for k, v in old["local_patches"].items()
                            if k in ("Cargo.lock", "src/frame/headers.rs")}
    assert not admitted(old), "old two-file inventory admitted after B-06 merge"
    extra = json.loads(json.dumps(original))
    extra["local_modifications"].append("src/unreviewed.rs")
    extra["local_patches"]["src/unreviewed.rs"] = {}
    assert not admitted(extra), "unreviewed h2 file admitted"
print("PASS: full-matrix CI steps and strict five-file h2 custody")
