"""Admission and deadline controls for the isolated installed deny verifier."""
import importlib.util
import json
from pathlib import Path
import subprocess
import time
from types import SimpleNamespace
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    'aegis_isolated_deny_monitor', ROOT / 'scripts/lib/aegis_auto_foreign_monitor.py')
MONITOR = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MONITOR)


class IsolatedDenyReadback(unittest.TestCase):
    def reply(self, **changes):
        value = {'state_sha256': 'a' * 64, 'policy_sha256': 'b' * 64,
                 'manager_binding_sha256': None}
        value.update(changes)
        return value

    def result(self, value=None, **changes):
        values = {'returncode': 0, 'stdout': json.dumps(
            self.reply() if value is None else value).encode(), 'stderr': b''}
        values.update(changes)
        return SimpleNamespace(**values)

    def test_closed_reply_uses_clean_installed_cli_and_remaining_deadline(self):
        with mock.patch.object(MONITOR.subprocess, 'run',
                               return_value=self.result()) as child:
            self.assertEqual(MONITOR._isolated_deny_policy_sha(time.monotonic() + 2),
                             ('a' * 64, 'b' * 64))
        args, options = child.call_args
        self.assertEqual(args[0], ('/usr/bin/python3', '-I', '-B',
            '/usr/local/lib/aegis/helpers/lib/aegis_auto_guardian.py', 'read-guard-policy'))
        self.assertLessEqual(options['timeout'], 2)
        self.assertGreater(options['timeout'], 0)
        self.assertEqual(options['env'],
                         {'PATH': '/usr/sbin:/usr/bin', 'LANG': 'C', 'LC_ALL': 'C'})

    def test_manager_binding_digest_is_optional_but_typed(self):
        with mock.patch.object(MONITOR.subprocess, 'run',
                return_value=self.result(self.reply(manager_binding_sha256='c' * 64))):
            self.assertEqual(MONITOR._isolated_deny_policy_sha(time.monotonic() + 20),
                             ('a' * 64, 'b' * 64))

    def test_foreign_or_malformed_replies_never_supply_a_deny_hash(self):
        replies = [[], {}, {**self.reply(), 'grant': True},
                   self.reply(state_sha256='A' * 64),
                   self.reply(policy_sha256=True),
                   self.reply(manager_binding_sha256=False),
                   self.reply(manager_binding_sha256='c' * 63)]
        missing = self.reply()
        del missing['manager_binding_sha256']
        replies.append(missing)
        for value in replies:
            with self.subTest(value=value), mock.patch.object(MONITOR.subprocess, 'run',
                    return_value=self.result(value)):
                with self.assertRaises(ValueError):
                    MONITOR._isolated_deny_policy_sha(time.monotonic() + 20)

    def test_child_failure_and_output_bounds_refuse(self):
        results = [self.result(returncode=1), self.result(stdout=b''),
                   self.result(stdout=b'{' + b'x' * 4096),
                   self.result(stderr=b'x' * 4097),
                   self.result(stdout=b'{"state_sha256":"a","state_sha256":"b"}')]
        for value in results:
            with self.subTest(value=value), mock.patch.object(MONITOR.subprocess, 'run',
                    return_value=value):
                with self.assertRaises(ValueError):
                    MONITOR._isolated_deny_policy_sha(time.monotonic() + 20)

    def test_expired_absolute_deadline_does_not_start_child(self):
        with mock.patch.object(MONITOR.subprocess, 'run') as child:
            with self.assertRaisesRegex(ValueError, 'assessment wait elapsed'):
                MONITOR._isolated_deny_policy_sha(time.monotonic() - 1)
            child.assert_not_called()

    def test_success_after_absolute_deadline_is_not_a_deny_proof(self):
        with mock.patch.object(MONITOR.time, 'monotonic', side_effect=(1.0, 3.0)), \
             mock.patch.object(MONITOR.subprocess, 'run', return_value=self.result()):
            with self.assertRaises(ValueError):
                MONITOR._isolated_deny_policy_sha(2.0)

    def test_child_timeout_is_not_retried(self):
        with mock.patch.object(MONITOR.subprocess, 'run',
                side_effect=subprocess.TimeoutExpired('guardian', 10)) as child:
            with self.assertRaises(subprocess.TimeoutExpired):
                MONITOR._isolated_deny_policy_sha(time.monotonic() + 20)
            self.assertEqual(child.call_count, 1)


if __name__ == '__main__':
    unittest.main()
