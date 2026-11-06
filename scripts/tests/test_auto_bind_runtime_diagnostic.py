"""Closed BindRuntimeService refusal coordinates; no host or package actions."""
import importlib.util
import json
import os
from pathlib import Path
import re
import tempfile
import time
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "scripts/lib/aegis_installer_auto_v2.py"
BACKEND = ROOT / "aegis-client/src/profile_auto_backend.rs"
SPEC = importlib.util.spec_from_file_location("aegis_bind_runtime_diagnostic_test", SOURCE)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
BIND = ["bind-runtime-service", "--service-user", "root"]


def rust_steps():
    """The Rust BIND_RUNTIME_STEPS literal, read from the committed source."""
    text = BACKEND.read_text(encoding="utf-8")
    body = re.findall(r"const BIND_RUNTIME_STEPS: &\[&str\] = &\[(.*?)\];", text, re.S)
    if len(body) != 1:
        raise AssertionError("one Rust BIND_RUNTIME_STEPS literal required")
    items = re.findall(r'"([a-z0-9_]+)",', body[0])
    if re.sub(r'\s|"[a-z0-9_]+",', "", body[0]):
        raise AssertionError("Rust BIND_RUNTIME_STEPS literal is not a plain list")
    return items


class Worker:
    def __init__(self):
        self.stdin = mock.Mock()

    def poll(self):
        return None


class BindRuntimeDiagnosticTests(unittest.TestCase):
    def failure(self, response, words=BIND):
        with mock.patch.object(MODULE, "fixed_lines",
                               return_value=json.dumps(response).encode() + b"\n"):
            with self.assertRaises(MODULE.Refused) as caught:
                MODULE.worker_phase(Worker(), words, time.monotonic())
        return caught.exception

    def record(self, phase, error):
        with tempfile.TemporaryDirectory() as temporary:
            held = lambda: os.open(temporary, os.O_RDONLY | os.O_DIRECTORY)
            with mock.patch.object(MODULE, "control_directory", side_effect=held):
                MODULE.record_failure({"phase": phase}, error)
            files = list(Path(temporary).glob("failure-*.json"))
            self.assertEqual(len(files), 1)
            raw = files[0].read_bytes()
        self.assertLessEqual(len(raw), 512)
        return json.loads(raw)

    def test_rust_and_python_step_lists_are_identical(self):
        steps = rust_steps()
        self.assertEqual(len(steps), len(set(steps)))
        self.assertEqual(set(steps), MODULE.BIND_RUNTIME_STEPS)
        self.assertEqual(len(steps), 43)
        self.assertIn("policy_compile_guard_hook_unrecognized", steps)

    def test_typed_bind_refusal_is_recorded_as_a_closed_coordinate(self):
        for step in sorted(MODULE.BIND_RUNTIME_STEPS):
            with self.subTest(step=step):
                error = self.failure({"status": "error", "reason": "phase_refused",
                                      "bind_runtime_step": step})
                self.assertEqual(error.bind_runtime_step, step)
                value = self.record("bind_runtime", error)
                self.assertEqual(value["bind_runtime_step"], step)
                self.assertEqual(value["reason"], "refused")
                self.assertEqual(value["phase"], "bind_runtime")
                self.assertEqual(set(value), {"schema", "phase", "reason", "worker_exit",
                                              "remaining_ms", "bind_runtime_step"})
        longest = max(MODULE.BIND_RUNTIME_STEPS, key=len)
        error = MODULE.Refused()
        error.bind_runtime_step = longest
        with tempfile.TemporaryDirectory() as temporary:
            held = lambda: os.open(temporary, os.O_RDONLY | os.O_DIRECTORY)
            worker = mock.Mock()
            worker.poll.return_value = -255
            with mock.patch.object(MODULE, "control_directory", side_effect=held):
                MODULE.record_failure({"phase": "bind_runtime", "worker": worker,
                                       "worker_started": time.monotonic()}, error)
            raw = next(Path(temporary).glob("failure-*.json")).read_bytes()
        self.assertLessEqual(len(raw), 512)
        self.assertEqual(json.loads(raw)["bind_runtime_step"], longest)

    def test_plain_refusal_is_still_admitted_without_a_coordinate(self):
        error = self.failure({"status": "error", "reason": "phase_refused"})
        self.assertFalse(hasattr(error, "bind_runtime_step"))
        value = self.record("bind_runtime", error)
        self.assertNotIn("bind_runtime_step", value)

    def test_begin_capture_retains_only_fixed_unit_pin_coordinates(self):
        for step in ("worker_pin_before", "worker_pin_after"):
            with self.subTest(step=step):
                error = self.failure({"status": "error", "reason": "phase_refused",
                                      "bind_runtime_step": step}, ["begin-capture"])
                self.assertEqual(error.bind_runtime_step, step)
                value = self.record("begin_capture", error)
                self.assertEqual(value["phase"], "begin_capture")
                self.assertEqual(value["reason"], "refused")
                self.assertEqual(value["bind_runtime_step"], step)
                self.assertNotIn("begin_capture_step", value)

    def test_coordinate_is_refused_outside_the_exact_bind_command(self):
        typed = {"status": "error", "reason": "phase_refused",
                 "bind_runtime_step": "policy_compile_guard_hook_unrecognized"}
        for words in (["begin-capture"], ["finalize"], ["bind-runtime-service"],
                      ["bind-runtime-service", "--service-user"],
                      ["bind-runtime-service", "--service-user", "root", "extra"],
                      ["commit-custody", "--service-user", "root"]):
            with self.subTest(words=words):
                self.assertFalse(hasattr(self.failure(typed, words), "bind_runtime_step"))
        for response in (dict(typed, reason="native_recovery_required"),
                         dict(typed, bind_runtime_step="/root/private"),
                         dict(typed, bind_runtime_step="policy_compile_guard_hook_unrecognized:x"),
                         dict(typed, bind_runtime_step=7),
                         dict(typed, bind_runtime_step=""),
                         dict(typed, extra="secret"),
                         dict(typed, begin_capture_step="launch_register")):
            with self.subTest(response=response):
                self.assertFalse(hasattr(self.failure(response), "bind_runtime_step"))
        error = MODULE.Refused()
        error.bind_runtime_step = "dispatch"
        with tempfile.TemporaryDirectory() as temporary:
            held = lambda: os.open(temporary, os.O_RDONLY | os.O_DIRECTORY)
            with mock.patch.object(MODULE, "control_directory", side_effect=held):
                with self.assertRaises(MODULE.Refused):
                    MODULE.record_failure({"phase": "begin_capture"}, error)
            self.assertEqual(list(Path(temporary).glob("failure-*.json")), [])
        for step in ("worker_pin_before", "worker_pin_after"):
            typed_pin = {"status": "error", "reason": "phase_refused",
                         "bind_runtime_step": step}
            for words in (["finalize"], ["rollback", "--capture-started", "0"]):
                self.assertFalse(hasattr(self.failure(typed_pin, words),
                                         "bind_runtime_step"))

    def test_abort_history_still_refuses_a_bind_failure_record(self):
        error = MODULE.Refused()
        error.bind_runtime_step = "policy_compile_guard_hook_unrecognized"
        value = self.record("bind_runtime", error)
        with tempfile.TemporaryDirectory() as temporary:
            name = "failure-" + "0" * 32 + ".json"
            (Path(temporary) / name).write_bytes(json.dumps(value).encode())
            with mock.patch.object(MODULE, "CONTROL", Path(temporary)), \
                    mock.patch.object(MODULE, "bounded_root_bytes",
                                      side_effect=lambda path, limit, modes: path.read_bytes()):
                with self.assertRaises(MODULE.Refused):
                    MODULE._abort_failure_history(temporary)


if __name__ == "__main__":
    unittest.main()
