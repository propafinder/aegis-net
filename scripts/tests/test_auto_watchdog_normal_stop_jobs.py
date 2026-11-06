#!/usr/bin/env python3
"""The watchdog must not create a second job after a proven normal stop."""
import subprocess
import sys
from pathlib import Path
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'lib'))
import aegis_auto_guardian_watchdog as watchdog


UNIT = 'aegis-auto@' + 'a' * 64 + '.service'
INERT = {'LoadState': 'loaded', 'ActiveState': 'inactive', 'MainPID': '0',
         'InvocationID': 'b' * 32, 'ControlGroup': ''}


class NormalStopJobs(unittest.TestCase):
    def test_proven_idle_unit_does_not_enqueue_second_stop(self):
        no_job = subprocess.CompletedProcess([], 0, b'Job=0\n', b'')
        with (mock.patch.object(watchdog.subprocess, 'run', return_value=no_job) as run,
              mock.patch.object(watchdog, '_unit_facts', return_value=INERT) as facts):
            self.assertEqual(watchdog._stop_private(
                UNIT, INERT, settled_normal_stop=True,
                expected_invocation='b' * 32), INERT)
        self.assertEqual(run.call_count, 1)
        self.assertEqual(run.call_args.args[0][:4],
                         ['/usr/bin/systemctl', 'show', UNIT, '-p'])
        facts.assert_called_once_with(UNIT)

    def test_unproven_or_pending_unit_keeps_pid1_stop(self):
        pending = subprocess.CompletedProcess([], 0, b'Job=4746\n', b'')
        stopped = subprocess.CompletedProcess(
            [], 0, b'o "/org/freedesktop/systemd1/job/4750"\n', b'')
        for proven, replies in ((False, [stopped]), (True, [pending, stopped])):
            with self.subTest(proven=proven):
                with (mock.patch.object(watchdog.subprocess, 'run', side_effect=replies) as run,
                      mock.patch.object(watchdog, '_unit_facts', return_value=INERT)):
                    self.assertEqual(watchdog._stop_private(
                        UNIT, INERT, settled_normal_stop=proven,
                        expected_invocation='b' * 32), INERT)
                self.assertTrue(any(call.args[0][0] == '/usr/bin/busctl'
                                    for call in run.call_args_list))

    def test_failed_job_readback_keeps_pid1_stop(self):
        stopped = subprocess.CompletedProcess(
            [], 0, b'o "/org/freedesktop/systemd1/job/4751"\n', b'')
        with (mock.patch.object(watchdog.subprocess, 'run',
                                side_effect=[subprocess.TimeoutExpired('show', 2), stopped]) as run,
              mock.patch.object(watchdog, '_unit_facts', return_value=INERT)):
            self.assertEqual(watchdog._stop_private(
                UNIT, INERT, settled_normal_stop=True,
                expected_invocation='b' * 32), INERT)
        self.assertEqual(run.call_args_list[-1].args[0][0], '/usr/bin/busctl')

    def test_foreign_invocation_cannot_take_settled_shortcut(self):
        no_job = subprocess.CompletedProcess([], 0, b'Job=0\n', b'')
        stopped = subprocess.CompletedProcess(
            [], 0, b'o "/org/freedesktop/systemd1/job/4752"\n', b'')
        foreign = {**INERT, 'InvocationID': 'c' * 32}
        for before, after in ((foreign, foreign), (INERT, foreign)):
            with self.subTest(before=before['InvocationID']):
                with (mock.patch.object(watchdog.subprocess, 'run',
                                        side_effect=[no_job, stopped] if before is INERT
                                        else [stopped]) as run,
                      mock.patch.object(watchdog, '_unit_facts', return_value=after)):
                    watchdog._stop_private(
                        UNIT, before, settled_normal_stop=True,
                        expected_invocation='b' * 32)
                self.assertTrue(any(call.args[0][0] == '/usr/bin/busctl'
                                    for call in run.call_args_list))


if __name__ == '__main__':
    unittest.main()
