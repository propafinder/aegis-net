"""A successful PID1 jobs query must also have a silent stderr channel."""
import sys
from pathlib import Path
import subprocess
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts/lib'))
import aegis_auto_guardian as guardian


class RotationJobStderrTests(unittest.TestCase):
    def check(self, stdout=b'', stderr=b'', returncode=0):
        response = subprocess.CompletedProcess([], returncode, stdout, stderr)
        with patch.object(guardian.subprocess, 'run', return_value=response) as run:
            try:
                guardian._rotation_actor_jobs(time.monotonic() + 2)
            finally:
                run.assert_called_once()

    def test_clean_empty_jobs_pass(self):
        self.check()

    def test_clean_unrelated_job_passes(self):
        self.check(b'19 ssh.service start running\n')

    def test_warning_with_empty_stdout_refuses(self):
        with self.assertRaisesRegex(guardian.Refused, 'rotation_actor_job_pending'):
            self.check(stderr=b'warning\n')

    def test_warning_with_unrelated_job_refuses(self):
        with self.assertRaisesRegex(guardian.Refused, 'rotation_actor_job_pending'):
            self.check(b'19 ssh.service start running\n', b'warning\n')

    def test_pending_aegis_job_remains_typed(self):
        row = b'351 aegis-device-dhcp-refresh.service start running\n'
        with self.assertRaisesRegex(guardian.RotationActorJobPending,
                                    'rotation_actor_job_pending'):
            self.check(row)

    def test_warning_pending_malformed_and_nonzero_remain_fail_closed(self):
        pending = b'351 aegis-device-dhcp-refresh.service start running\n'
        for stdout, stderr, code in ((pending, b'warning\n', 0),
                                     (b'bad aegis-device-dhcp-refresh.service start running\n', b'', 0),
                                     (pending, b'', 1)):
            with self.subTest(stdout=stdout, stderr=stderr, code=code):
                with self.assertRaisesRegex(guardian.Refused,
                                            'rotation_actor_job_pending') as caught:
                    self.check(stdout, stderr, code)
                self.assertIs(type(caught.exception), guardian.Refused)

    def test_elapsed_deadline_still_refuses_before_query(self):
        with patch.object(guardian.subprocess, 'run') as run:
            with self.assertRaisesRegex(guardian.Refused,
                                        'rotation_actor_deadline_elapsed'):
                guardian._rotation_actor_jobs(time.monotonic() - 1)
        run.assert_not_called()


if __name__ == '__main__':
    unittest.main()
