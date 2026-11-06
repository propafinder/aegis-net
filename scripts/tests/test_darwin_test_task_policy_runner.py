"""Inert admission controls for the targeted Darwin Cargo test runner."""

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import struct
import tempfile
import time
import unittest
from unittest import mock


SOURCE = Path(__file__).resolve().parents[1] / "qa/darwin-test-task-policy-runner-r1.py"
SPEC = importlib.util.spec_from_file_location("darwin_policy_runner", SOURCE)
RUNNER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RUNNER)


def proof(mode="normalize"):
    return {"schema": RUNNER.SCHEMA, "pid": 123, "mode": RUNNER.MODES[mode],
            "nonce": "a" * 32,
            "before_latency": RUNNER.TIER3, "seeded_latency": RUNNER.TIER3,
            "after_latency": RUNNER.TIER0 if mode.endswith("normalize") else RUNNER.TIER3,
            "before_throughput": 0xFE0002, "after_throughput": 0xFE0002,
            "before_bg": 0, "after_bg": 0, "before_nice": -10,
            "after_nice": -10, "before_role": 0, "after_role": 0,
            "before_qos": 21, "after_qos": 21}


class RunnerAdmissionTests(unittest.TestCase):
    def test_exited_sole_leader_is_reaped_without_killpg(self):
        child = mock.Mock(pid=123)
        child.wait.return_value = 0
        with mock.patch.object(RUNNER, "exited_unreaped", return_value=True), \
             mock.patch.object(RUNNER, "group_members", return_value=set()) as members, \
             mock.patch.object(RUNNER.os, "killpg") as kill:
            self.assertEqual(RUNNER.close_group(child, force=True), 0)
        kill.assert_not_called()
        self.assertEqual(members.call_count, 2)
        child.wait.assert_called_once_with(timeout=2)

    def test_exited_leader_with_zombie_descendant_requires_group_closure(self):
        child = mock.Mock(pid=123)
        child.wait.return_value = 0
        # group_members includes zombies, just like the frozen C15 helper.
        with mock.patch.object(RUNNER, "exited_unreaped", return_value=True), \
             mock.patch.object(RUNNER, "group_members",
                               side_effect=[{124}, set(), set()]), \
             mock.patch.object(RUNNER.os, "killpg") as kill:
            self.assertEqual(RUNNER.close_group(child, force=False), 0)
        kill.assert_called_once_with(123, RUNNER.signal.SIGTERM)

    def test_exact_constructor_proof_and_policy_drift_refusals(self):
        RUNNER.proof_shape(proof(), 123, "normalize", "a" * 32)
        for field, replacement in (("pid", 124), ("mode", 0),
                                   ("after_latency", RUNNER.TIER3),
                                   ("after_throughput", 1),
                                   ("after_nice", 0), ("after_role", 2),
                                   ("after_qos", 9), ("nonce", "b" * 32)):
            with self.subTest(field=field), self.assertRaises(RuntimeError):
                RUNNER.proof_shape({**proof(), field: replacement}, 123,
                                   "normalize", "a" * 32)
        with self.assertRaises(RuntimeError):
            RUNNER.proof_shape({**proof(), "extra": 1}, 123, "normalize", "a" * 32)
        with self.assertRaises(RuntimeError):
            RUNNER.proof_shape({**proof(), "seeded_latency": 0}, 123,
                               "selftest_seed3_normalize", "a" * 32)
        with self.assertRaises(RuntimeError):
            RUNNER.proof_shape({**proof(), "before_latency": RUNNER.TIER0}, 123,
                               "selftest_seed3_normalize", "a" * 32)

    def test_utility_context_requires_default_qos_after_normalization(self):
        for mode in ("normalize", "selftest_utility_normalize"):
            row = {**proof(), "mode": RUNNER.MODES[mode],
                   "before_qos": 17, "before_latency": RUNNER.TIER0,
                   "seeded_latency": RUNNER.TIER0}
            RUNNER.proof_shape(row, 123, mode, "a" * 32)
            for qos in (0, 9, 17, 25, 33):
                with self.subTest(mode=mode, qos=qos), self.assertRaises(RuntimeError):
                    RUNNER.proof_shape({**row, "after_qos": qos}, 123, mode, "a" * 32)
        row = {**row, "mode": RUNNER.MODES["selftest_utility"], "after_qos": 17}
        RUNNER.proof_shape(row, 123, "selftest_utility", "a" * 32)
        with self.assertRaises(RuntimeError):
            RUNNER.proof_shape({**row, "after_qos": 21}, 123, "selftest_utility", "a" * 32)

    def test_pipe_requires_exactly_one_bounded_record(self):
        for raw, accepted in ((json.dumps(proof()).encode() + b"\n", True),
                              (b"", False),
                              ((json.dumps(proof()) + "\n") * 2, False),
                              (b"x" * 1025 + b"\n", False)):
            read, write = os.pipe()
            try:
                os.write(write, raw.encode() if isinstance(raw, str) else raw)
                os.close(write)
                with self.subTest(size=len(raw)):
                    if accepted:
                        self.assertEqual(RUNNER.read_proof(read, time.monotonic() + 1),
                                         proof())
                    else:
                        with self.assertRaises((RuntimeError, ValueError)):
                            RUNNER.read_proof(read, time.monotonic() + 1)
            finally:
                os.close(read)

    def test_macho_type_hash_symlink_and_hardlink_admission(self):
        with tempfile.TemporaryDirectory(prefix="aegis-darwin-policy-inert-") as temp:
            root = Path(temp).resolve()
            target = root / "test-exe"
            header = b"\xcf\xfa\xed\xfe" + b"\0" * 8 + struct.pack("<I", 2)
            target.write_bytes(header + b"\0" * 16)
            target.chmod(0o700)
            pin = hashlib.sha256(target.read_bytes()).hexdigest()
            RUNNER.regular_macho(target, root, pin, 2)
            with self.assertRaises(RuntimeError):
                RUNNER.regular_macho(target, root, "0" * 64, 2)
            with self.assertRaises(RuntimeError):
                RUNNER.regular_macho(target, root, pin, 6)
            with self.assertRaises(RuntimeError):
                RUNNER.regular_macho(root / ".." / root.name / "test-exe", root,
                                     pin, 2)
            alias = root / "alias"
            alias.symlink_to(target)
            with self.assertRaises(RuntimeError):
                RUNNER.regular_macho(alias, root, pin, 2)
            alias.unlink()
            os.link(target, alias)
            with self.assertRaises(RuntimeError):
                RUNNER.regular_macho(target, root, pin, 2)

    def test_exact_argv_and_single_dyld_target_without_prior_injection(self):
        with tempfile.TemporaryDirectory(prefix="aegis-darwin-runner-inert-") as temp:
            root = Path(temp)
            exe = root / "test-exe"
            library = root / "witness.dylib"
            args = mock.Mock(repo=root, commit="a" * 40, manifest=root / "manifest",
                             manifest_sha="b" * 64, runner_sha="c" * 64,
                             execution=root, library=library,
                             library_sha="d" * 64, target_root=root,
                             test_sha="e" * 64, mode="normalize",
                             timeout_seconds=10, command=[str(exe), "--test-threads=1"])
            child = mock.Mock(pid=123, returncode=None)
            child.wait.return_value = 0
            evidence = []

            def launch(argv, **kwargs):
                evidence.append((argv, kwargs))
                return child

            def close(*_args, **_kwargs):
                child.returncode = 0
                return 0

            with mock.patch.object(RUNNER, "source_gate") as source_check, \
                 mock.patch.object(RUNNER, "regular_macho") as target_check, \
                 mock.patch.object(RUNNER.secrets, "token_hex", return_value="a" * 32), \
                 mock.patch.object(RUNNER.subprocess, "Popen", side_effect=launch), \
                 mock.patch.object(RUNNER, "read_proof", return_value=proof()), \
                 mock.patch.object(RUNNER, "exited_unreaped", return_value=True), \
                 mock.patch.object(RUNNER, "close_group", side_effect=close), \
                 mock.patch.dict(os.environ, {}, clear=True):
                self.assertEqual(RUNNER.run(args), 0)
            self.assertEqual(source_check.call_count, 2)
            self.assertEqual(target_check.call_count, 4)
            self.assertEqual(evidence[0][0], args.command)
            self.assertEqual(evidence[0][1]["env"]["DYLD_INSERT_LIBRARIES"],
                             str(library))
            self.assertEqual(evidence[0][1]["env"]["AEGIS_DARWIN_POLICY_EXE"],
                             str(exe))
            self.assertEqual(evidence[0][1]["stdout"], None)
            self.assertEqual(evidence[0][1]["stderr"], None)
            with mock.patch.dict(os.environ, {"DYLD_INSERT_LIBRARIES": "foreign.dylib"}):
                with self.assertRaises(RuntimeError):
                    RUNNER.run(args)
            args.mode = "selftest_seed3"
            with mock.patch.object(RUNNER, "source_gate"), \
                 mock.patch.object(RUNNER, "regular_macho"):
                with self.assertRaises(RuntimeError):
                    RUNNER.run(args)

    def test_sigterm_during_spawn_closes_only_assigned_child(self):
        with tempfile.TemporaryDirectory(prefix="aegis-darwin-signal-inert-") as temp:
            root = Path(temp).resolve()
            args = mock.Mock(repo=root, commit="a" * 40, manifest=root / "manifest",
                             manifest_sha="b" * 64, runner_sha="c" * 64,
                             execution=root, library=root / "witness.dylib",
                             library_sha="d" * 64, target_root=root,
                             test_sha="e" * 64, mode="observe",
                             timeout_seconds=10, command=[str(root / "test-exe")])
            child = mock.Mock(pid=123, returncode=None)
            closed = []
            def launch(*_args, **_kwargs):
                # The installed handler records interruption without raising
                # between Popen's return and child assignment.
                os.kill(os.getpid(), 15)
                return child
            def close(_child, force):
                closed.append(force)
                child.returncode = -15
                return -15
            with mock.patch.object(RUNNER, "source_gate"), \
                 mock.patch.object(RUNNER, "regular_macho"), \
                 mock.patch.object(RUNNER.subprocess, "Popen", side_effect=launch), \
                 mock.patch.object(RUNNER, "read_proof", return_value=proof("observe")), \
                 mock.patch.object(RUNNER, "close_group", side_effect=close), \
                 mock.patch.object(RUNNER.secrets, "token_hex", return_value="a" * 32), \
                 mock.patch.dict(os.environ, {}, clear=True):
                with self.assertRaises(RuntimeError):
                    RUNNER.run(args)
            self.assertEqual(closed, [True])


if __name__ == "__main__":
    unittest.main()
