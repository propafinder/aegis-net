"""Closed worker failure diagnostics do not authorize retries or expose inputs."""
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

SOURCE = Path(__file__).resolve().parents[1] / "lib" / "aegis_installer_auto_v2.py"
SPEC = importlib.util.spec_from_file_location("aegis_start_diagnostic_test", SOURCE)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class StartDiagnostics(unittest.TestCase):
    def test_authenticated_capture_refusal_retains_only_closed_coordinates(self):
        coordinate = {"reason": "os_error", "source": "endpoint", "line": 412}
        proc = mock.Mock()
        proc.poll.return_value = None
        with mock.patch.object(MODULE, "fixed_lines", return_value=json.dumps({
                "status": "error", "reason": "phase_refused",
                "begin_capture_step": "capture_ready",
                "capture_refusal": coordinate}).encode()):
            with self.assertRaises(MODULE.Refused) as caught:
                MODULE.worker_phase(proc, ["begin-capture"], MODULE.time.monotonic())
        self.assertEqual(caught.exception.capture_refusal, coordinate)
        with tempfile.TemporaryDirectory() as temporary:
            held = lambda: os.open(temporary, os.O_RDONLY | os.O_DIRECTORY)
            with mock.patch.object(MODULE, "control_directory", side_effect=held):
                MODULE.record_failure({"phase": "begin_capture"}, caught.exception)
            value = json.loads(next(Path(temporary).glob("failure-*.json")).read_bytes())
            self.assertEqual(value["capture_refusal"], coordinate)
            self.assertEqual(value["begin_capture_step"], "capture_ready")
            self.assertEqual(value["reason"], "refused")
            self.assertNotIn("worker_diagnostic", value)

    def test_capture_refusal_rejects_private_fields_and_other_phases(self):
        proc = mock.Mock()
        proc.poll.return_value = None
        good = {"reason": "os_error", "source": "endpoint", "line": 412}
        for bad in [dict(good, reason="private error"),
                    dict(good, source="/root/private"),
                    dict(good, line=0), dict(good, line=10_001),
                    dict(good, line=True), dict(good, private="invitation")]:
            with self.assertRaises(MODULE.Refused):
                MODULE.capture_refusal_diagnostic(bad)
        for step in ["/root/private", "capture_ready:private", True, ""]:
            with self.assertRaises(MODULE.Refused):
                MODULE.begin_capture_step(step)
        for words, reason in [(["finalize"], "phase_refused"),
                              (["begin-capture"], "native_recovery_required")]:
            with mock.patch.object(MODULE, "fixed_lines", return_value=json.dumps({
                    "status": "error", "reason": reason,
                    "capture_refusal": good}).encode()):
                with self.assertRaises(MODULE.Refused) as caught:
                    MODULE.worker_phase(proc, words, MODULE.time.monotonic())
                self.assertFalse(hasattr(caught.exception, "capture_refusal"))
        for step in ["pid1_start", "launch_record"]:
            with mock.patch.object(MODULE, "fixed_lines", return_value=json.dumps({
                    "status": "error", "reason": "phase_refused",
                    "begin_capture_step": step,
                    "capture_refusal": good}).encode()):
                with self.assertRaises(MODULE.Refused) as caught:
                    MODULE.worker_phase(proc, ["begin-capture"], MODULE.time.monotonic())
                self.assertFalse(hasattr(caught.exception, "capture_refusal"))
                self.assertFalse(hasattr(caught.exception, "begin_capture_step"))

    def test_begin_capture_step_persists_generic_refusal_without_raw_error(self):
        proc = mock.Mock()
        proc.poll.return_value = None
        with mock.patch.object(MODULE, "fixed_lines", return_value=json.dumps({
                "status": "error", "reason": "phase_refused",
                "begin_capture_step": "launch_register"}).encode()):
            with self.assertRaises(MODULE.Refused) as caught:
                MODULE.worker_phase(proc, ["begin-capture"], MODULE.time.monotonic())
        with tempfile.TemporaryDirectory() as temporary:
            held = lambda: os.open(temporary, os.O_RDONLY | os.O_DIRECTORY)
            with mock.patch.object(MODULE, "control_directory", side_effect=held):
                MODULE.record_failure({"phase": "begin_capture"}, caught.exception)
            value = json.loads(next(Path(temporary).glob("failure-*.json")).read_bytes())
            self.assertEqual(value["begin_capture_step"], "launch_register")
            self.assertEqual(value["reason"], "refused")
            self.assertNotIn("capture_refusal", value)
            self.assertNotIn("worker_diagnostic", value)
        with mock.patch.object(MODULE, "fixed_lines", return_value=json.dumps({
                "status": "error", "reason": "phase_refused",
                "begin_capture_step": "launch_register"}).encode()):
            with self.assertRaises(MODULE.Refused) as wrong:
                MODULE.worker_phase(proc, ["finalize"], MODULE.time.monotonic())
            self.assertFalse(hasattr(wrong.exception, "begin_capture_step"))

    def test_terminal_registrar_coordinates_cross_worker_and_failure_receipt(self):
        proc = mock.Mock()
        proc.poll.return_value = None
        for step in ("terminal_configure", "terminal_recover_incomplete",
                     "terminal_prepare", "terminal_activate"):
            payload = json.dumps({"status": "error", "reason": "phase_refused",
                                  "begin_capture_step": step}).encode() + b"\n"
            with mock.patch.object(MODULE, "fixed_lines", return_value=payload):
                with self.assertRaises(MODULE.Refused) as caught:
                    MODULE.worker_phase(proc, ["begin-capture"], MODULE.time.monotonic())
            self.assertEqual(caught.exception.begin_capture_step, step)
            with tempfile.TemporaryDirectory() as temporary:
                held = lambda: os.open(temporary, os.O_RDONLY | os.O_DIRECTORY)
                with mock.patch.object(MODULE, "control_directory", side_effect=held):
                    MODULE.record_failure({"phase": "begin_capture"}, caught.exception)
                record = json.loads(next(Path(temporary).glob("failure-*.json")).read_bytes())
                self.assertEqual(record["begin_capture_step"], step)
                self.assertEqual(record["reason"], "refused")
                self.assertNotIn("diagnostic", record)
            with mock.patch.object(MODULE, "fixed_lines", return_value=payload):
                with self.assertRaises(MODULE.Refused) as wrong_phase:
                    MODULE.worker_phase(proc, ["finalize"], MODULE.time.monotonic())
            self.assertFalse(hasattr(wrong_phase.exception, "begin_capture_step"))
        with self.assertRaises(MODULE.Refused):
            MODULE.begin_capture_step("terminal_private")

    def test_start_failure_diagnostic_is_closed_and_still_refuses(self):
        diagnostic = {"phase": "post_submit", "cause": "deny_lease", "errno": 0}
        proc = mock.Mock()
        proc.poll.return_value = None
        with mock.patch.object(MODULE, "fixed_lines", return_value=json.dumps({
                "status": "error", "reason": "native_recovery_required",
                "diagnostic": diagnostic}).encode()):
            with self.assertRaises(MODULE.Refused) as caught:
                MODULE.worker_phase(proc, ["begin-capture"], MODULE.time.monotonic())
        self.assertEqual(caught.exception.worker_diagnostic, diagnostic)
        with tempfile.TemporaryDirectory() as temporary:
            held = lambda: os.open(temporary, os.O_RDONLY | os.O_DIRECTORY)
            with mock.patch.object(MODULE, "control_directory", side_effect=held):
                MODULE.record_failure({"phase": "begin_capture"}, caught.exception)
            value = json.loads(next(Path(temporary).glob("failure-*.json")).read_bytes())
            self.assertEqual(value["worker_diagnostic"], diagnostic)
            self.assertEqual(value["reason"], "refused")

    def test_start_failure_diagnostic_rejects_open_payloads_and_wrong_phase(self):
        proc = mock.Mock()
        proc.poll.return_value = None
        good = {"phase": "submit", "cause": "io", "errno": 0}
        for bad in [dict(good, phase="secret-path"), dict(good, cause="private-key"),
                    dict(good, errno=True), dict(good, errno=4096),
                    dict(good, private="invitation"), {"phase": "submit"}]:
            with self.assertRaises(MODULE.Refused):
                MODULE.start_failure_diagnostic(bad)
        for words, reason in [(["finalize"], "native_recovery_required"),
                              (["begin-capture"], "phase_refused")]:
            with mock.patch.object(MODULE, "fixed_lines", return_value=json.dumps({
                    "status": "error", "reason": reason, "diagnostic": good}).encode()):
                with self.assertRaises(MODULE.Refused) as caught:
                    MODULE.worker_phase(proc, words, MODULE.time.monotonic())
                self.assertFalse(hasattr(caught.exception, "worker_diagnostic"))


if __name__ == "__main__":
    unittest.main()
