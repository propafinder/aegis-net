"""STOP_INVERSE owns its received FDs exactly once, even on refusal."""

import importlib.util
import os
from pathlib import Path
import unittest
from unittest import mock

SOURCE = Path(__file__).resolve().parents[1] / "lib/aegis_auto_guardian.py"
SPEC = importlib.util.spec_from_file_location("aegis_auto_guardian", SOURCE)
guardian = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(guardian)


class StopInverseDescriptorTests(unittest.TestCase):
    def exercise_inverse(self, *, proof_error=None, completion_error=None):
        actor = guardian.Guardian()
        request = {"command": "STOP_INVERSE", "unit": "test-unit"}
        stage_fd, install_fd, guard_fd, pidfd, assessment_fd = (
            os.open(os.devnull, os.O_RDONLY) for _ in range(5)
        )
        fds = (stage_fd, install_fd, guard_fd, pidfd, assessment_fd)
        watchdog = mock.Mock()
        watchdog.borrow_guard_fd.return_value = guard_fd
        actor.watchdogs[request["unit"]] = watchdog
        peer = mock.Mock()
        peer.sendmsg.side_effect = lambda buffers, _ancillary: len(buffers[0])
        proof = {"schema": "test-proof"}
        real_close = os.close
        with mock.patch.object(guardian.os, "close", wraps=real_close) as close_call, \
             mock.patch.object(guardian, "record", return_value={"worker_sha256": "f" * 64}), \
             mock.patch.object(guardian, "_unit_identity", return_value={}), \
             mock.patch.object(guardian, "_peer_identity", return_value=(os.getpid(), pidfd)), \
             mock.patch.object(guardian, "_receive", return_value=(request, (stage_fd, install_fd))), \
             mock.patch.object(guardian, "_peer_executable"), \
             mock.patch.object(guardian, "_stop_assessment_reservation", return_value=assessment_fd), \
             mock.patch.object(guardian, "_held_lock"), \
             mock.patch.object(guardian, "_pid_alive", return_value=True), \
             mock.patch.object(guardian, "_fresh_stop_inverse", side_effect=proof_error or [proof]), \
             mock.patch.object(guardian, "_receive_no_fds", return_value=b"INVERSE_COMPLETE\n"), \
             mock.patch.object(guardian, "_complete_fresh_stop_inverse", side_effect=completion_error):
            try:
                if proof_error or completion_error:
                    expected = proof_error or completion_error
                    with self.assertRaises(type(expected)) as caught:
                        actor.serve_one(peer)
                    self.assertIs(caught.exception, expected)
                else:
                    actor.serve_one(peer)
                    peer.sendall.assert_called_once_with(b"COMPLETE\n")
                    watchdog.disarm.assert_called_once_with()
            finally:
                closed = [call.args[0] for call in close_call.call_args_list]
                for fd in fds:
                    self.assertEqual(closed.count(fd), 1, (fd, closed))
                    with self.assertRaises(OSError):
                        os.fstat(fd)

    def test_proof_refusal_remains_primary_after_all_fd_cleanup(self):
        self.exercise_inverse(proof_error=guardian.Refused("original_inverse_refusal"))

    def test_completion_refusal_remains_primary_after_all_fd_cleanup(self):
        self.exercise_inverse(completion_error=guardian.Refused("original_completion_refusal"))

    def test_success_closes_received_fds_once_and_replies(self):
        self.exercise_inverse()


if __name__ == "__main__":
    unittest.main()
