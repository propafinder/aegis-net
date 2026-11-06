#!/usr/bin/env python3
"""Check real source admission and mocked CI calls without native operations."""
from pathlib import Path
import re
import hashlib
import importlib.util
import sys
from unittest import mock
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
PIN = "97c453a0e733d841f9dec5696d7be3a68550802bd3326a24b67fcc1c4935e5bc"


def invocation(source):
    marker = "      - name: Native device guard emitted nft batches (isolated)\n"
    assert source.count(marker) == 1, "unique CI step required"
    step = source.split(marker, 1)[1].split("\n      - name:", 1)[0]
    match = re.search(r"^        run: \|\n(.*)$", step, re.M | re.S)
    assert match, "literal run block required"
    lines = match[1].splitlines()
    while lines and not lines[-1].strip():
        lines.pop()
    expected = [
        "          set -euo pipefail",
        "          mkdir -p ./ci-output/device-guard",
        "          sudo -n python3 -I ./scripts/test-device-egress-guard-native.py " + chr(92),
        '            --repo-root "${GITHUB_WORKSPACE}" \\',
        '            --output-name "audit17-native-${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}" \\',
        "            --reviewed-driver-sha " + PIN + " " + chr(92),
        "            --root-reviewed-source-and-tools --sole-root-lease",
    ]
    assert lines == expected, "exact single reviewed privilege invocation required"
    # Do not execute setup, the workflow, or any driver source. Only this closed
    # literal invocation is copied into a shell whose sudo/python are mocks.
    return "\n".join(line.strip() for line in lines[2:]) + "\n"


def handoff_invocation(source):
    marker = "      - name: Hand off current isolated device guard evidence\n"
    assert source.count(marker) == 1, "unique handoff required"
    step = source.split(marker, 1)[1].split("\n      - name:", 1)[0]
    expected = (
        "        if: always()\n        timeout-minutes: 1\n        run: |\n"
        "          set -euo pipefail\n"
        "          sudo -n python3 -I ./scripts/handoff-deviceguard-ci-evidence.py " + chr(92) + "\n"
        '            --workspace "${GITHUB_WORKSPACE}" ' + chr(92) + "\n"
        '            --run "${GITHUB_RUN_ID}" --attempt "${GITHUB_RUN_ATTEMPT}" ' + chr(92) + "\n"
        '            --uid "$(id -u)" --gid "$(id -g)"\n'
    )
    assert step.rstrip("\n") == expected.rstrip("\n"), "closed current-evidence handoff required"
    return "\n".join(line.strip() for line in step.splitlines()[4:]) + "\n"


class PrivilegeContract(unittest.TestCase):
    def setUp(self):
        self.source = (ROOT / ".github/workflows/ci.yml").read_text()

    def test_real_source_binding_reaches_tools_only_for_matching_v1_contract(self):
        source = ROOT / "scripts/test-device-egress-guard-native.py"
        self.assertEqual(hashlib.sha256(source.read_bytes()).hexdigest(), PIN)
        spec = importlib.util.spec_from_file_location("native_guard_admission", source)
        native = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(native)
        class ToolsBoundary(Exception):
            pass
        with tempfile.TemporaryDirectory(prefix="aegis-guard-source-admission-") as temp:
            root = Path(temp).resolve()
            (root / "scripts").mkdir()
            helper = root / "scripts/aegis-device-egress-guard.sh"
            contract = root / "scripts/test-device-egress-guard-contract.sh"
            original_helper = (ROOT / "scripts/aegis-device-egress-guard.sh").read_bytes()
            original_contract = (ROOT / "scripts/test-device-egress-guard-contract.sh").read_bytes()
            helper.write_bytes(original_helper)
            argv = [str(source), "--repo-root", str(root), "--output-name", "audit17-native-inert-source",
                    "--reviewed-driver-sha", PIN, "--root-reviewed-source-and-tools", "--sole-root-lease"]
            with mock.patch.object(sys, "argv", argv), mock.patch.object(sys, "platform", "linux"), \
                 mock.patch.object(native.os, "geteuid", return_value=0), \
                 mock.patch.object(native.shutil, "which", side_effect=ToolsBoundary):
                contract.write_bytes(original_contract)
                with self.assertRaises(ToolsBoundary):
                    native.main()
                # This is the actual wrong-family input from the failed CI pin.
                contract.write_bytes((ROOT / "scripts/test-device-egress-guard-v2-contract.sh").read_bytes())
                with self.assertRaisesRegex(AssertionError, "guard source/contract changed"):
                    native.main()
                contract.write_bytes(original_contract)
                helper.write_bytes(original_helper + b"\n")
                with self.assertRaisesRegex(AssertionError, "guard source/contract changed"):
                    native.main()

    def test_exact_reviewed_call_with_mock_privilege(self):
        self.check_mock(False)

    def test_refused_privilege_never_invokes_driver_or_falls_back(self):
        self.check_mock(True)

    def test_exact_handoff_call_with_mock_runner_identity(self):
        self.check_mock(False, handoff=True)

    def test_refused_handoff_privilege_never_invokes_helper(self):
        self.check_mock(True, handoff=True)

    def check_mock(self, denied, handoff=False):
        call = handoff_invocation(self.source) if handoff else invocation(self.source)
        with tempfile.TemporaryDirectory(prefix="aegis-ci-privilege-inert-") as directory:
            fixture = Path(directory)
            sudo = fixture / "sudo"
            sudo.write_text('#!/bin/sh\n[ "$1" = "-n" ] || exit 24\nshift\n'
                            '[ "$FIXTURE_DENIED" = 0 ] || exit 23\nexec "$@"\n')
            python = fixture / "python3"
            python.write_text('#!/bin/sh\nprintf "%s\\n" "$@" > "$FIXTURE_ARGS"\n')
            sudo.chmod(0o755)
            python.chmod(0o755)
            identity = fixture / "id"
            identity.write_text('#!/bin/sh\ncase "$1" in -u|-g) printf "1001\\n";; *) exit 24;; esac\n')
            identity.chmod(0o755)
            record = fixture / "arguments"
            environment = {
                "PATH": str(fixture), "GITHUB_WORKSPACE": str(fixture / "workspace with spaces"),
                "GITHUB_RUN_ID": "123", "GITHUB_RUN_ATTEMPT": "2",
                "FIXTURE_DENIED": "1" if denied else "0", "FIXTURE_ARGS": str(record),
            }
            result = subprocess.run(["/bin/bash", "-c", "set -euo pipefail\n" + call],
                                    cwd=fixture, env=environment, stdin=subprocess.DEVNULL,
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=8)
            self.assertEqual(result.returncode, 23 if denied else 0)
            if denied:
                self.assertFalse(record.exists())
            else:
                expected = [
                    "-I", "./scripts/test-device-egress-guard-native.py", "--repo-root",
                    environment["GITHUB_WORKSPACE"], "--output-name", "audit17-native-123-2",
                    "--reviewed-driver-sha", PIN, "--root-reviewed-source-and-tools", "--sole-root-lease",
                ]
                if handoff:
                    expected = ["-I", "./scripts/handoff-deviceguard-ci-evidence.py", "--workspace",
                                environment["GITHUB_WORKSPACE"], "--run", "123", "--attempt", "2",
                                "--uid", "1001", "--gid", "1001"]
                self.assertEqual(record.read_text().splitlines(), expected)

    def test_unreviewed_or_fallback_invocations_refused_before_spawn(self):
        for source in (
            self.source.replace("sudo -n python3", "python3", 1),
            self.source.replace("sudo -n python3", "sudo -n -E python3", 1),
            self.source.replace("sudo -n python3", "sudo -n python3; /bin/false", 1),
            self.source.replace("--sole-root-lease", "--sole-root-lease || python3 fallback", 1),
            self.source.replace(PIN, "0" * 64, 1),
        ):
            with self.assertRaises(AssertionError):
                invocation(source)


if __name__ == "__main__":
    unittest.main()
