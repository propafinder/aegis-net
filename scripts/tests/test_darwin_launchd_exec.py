"""Private launch context and environment boundary controls."""
import importlib.util
from pathlib import Path
import unittest
import tempfile
from types import SimpleNamespace
from unittest import mock
S = importlib.util.spec_from_file_location('launchd_exec', Path(__file__).resolve().parents[1] / 'qa/darwin-launchd-exec-r1.py')
M = importlib.util.module_from_spec(S);S.loader.exec_module(M)


class LaunchContextTests(unittest.TestCase):
    def test_private_job_is_interactive_once_and_has_bounded_shutdown(self):
        row = {'label': 'org.aegis.ci.ne.' + 'a' * 32, 'python': '/python', 'bundle': '/private/bundle',
               'bundle_sha': 'b' * 64, 'repo': '/source', 'execution': '/private', 'env': {'PATH': '/bin'},
               'nofile': [10240, M.resource.RLIM_INFINITY], 'nice': -10}
        job = M.job_plist(row)
        self.assertEqual(job['ProcessType'], 'Interactive')
        self.assertFalse(job['KeepAlive']);self.assertFalse(job['AbandonProcessGroup'])
        self.assertEqual(job['ExitTimeOut'], 20);self.assertEqual(job['Umask'], 0o077)
        self.assertEqual(job['ProgramArguments'][-3:], ['--worker', '/private/bundle', 'b' * 64])
        self.assertNotIn('UserName', job)
        self.assertEqual(job['Nice'], -10)
        self.assertEqual(job['SoftResourceLimits'], {'NumberOfFiles': 10240})
        self.assertNotIn('HardResourceLimits', job)
        finite = M.job_plist({**row, 'nofile': [4096, 8192]})
        self.assertEqual(finite['HardResourceLimits'], {'NumberOfFiles': 8192})

    def test_bootout_and_absence_run_after_exited_or_failed_signal(self):
        with tempfile.TemporaryDirectory() as temp:
            (Path(temp) / 'worker-result.json').write_text('{}')
            row = {'domain': 'gui/501', 'label': 'owned', 'execution': temp}
            for error in (False, True):
                calls = []
                def run(argv, **kwargs):
                    calls.append(argv[1])
                    if argv[1] == 'kill':
                        self.assertIn(3, kwargs['valid'])
                        if error:
                            raise RuntimeError('injected_signal_failure')
                        return SimpleNamespace(returncode=3)
                    return SimpleNamespace(returncode=113 if argv[1] == 'print' else 0)
                with mock.patch.object(M, 'run', side_effect=run):
                    if error:
                        with self.assertRaisesRegex(RuntimeError, 'injected_signal_failure'):
                            M.stop_job(row)
                    else:
                        M.stop_job(row)
                self.assertEqual(calls, ['kill', 'bootout', 'print'])

    def test_resource_readback_refuses_before_any_command(self):
        with tempfile.TemporaryDirectory() as temp:
            row = {'execution': temp, 'nofile': [8192, M.resource.RLIM_INFINITY], 'nice': -10, 'argv': ['/never-executed']}
            c15 = mock.Mock()
            with mock.patch.object(M, 'helpers', return_value=(mock.Mock(), c15)), \
                 mock.patch.object(M.resource, 'getrlimit', return_value=tuple(row['nofile'])), \
                 mock.patch.object(M.resource, 'setrlimit'), \
                 mock.patch.object(M.os, 'getpriority', return_value=0):
                self.assertEqual(M.worker(row), 73)
            c15.one.assert_not_called()
            import json
            refused = json.loads((Path(temp) / 'worker-result.json').read_text())
            self.assertTrue(refused['command_closed'])
            self.assertFalse(refused['command']['executed'])
            self.assertFalse(refused['command']['passed'])

    def test_environment_keeps_build_controls_without_credentials_or_injection(self):
        for name in ('GITHUB_TOKEN', 'AWS_SECRET_ACCESS_KEY', 'DYLD_INSERT_LIBRARIES', 'AEGIS_BUNDLE_TOKEN'):
            self.assertNotIn(name, M.ENV_KEYS)
        for name in ('MACOSX_DEPLOYMENT_TARGET', 'PKG_CONFIG_LIBDIR', 'CARGO_TARGET_DIR', 'AEGIS_B06_TIMING_TRACE',
                     'CARGO_PROFILE_TEST_OPT_LEVEL', 'CARGO_PROFILE_TEST_DEBUG_ASSERTIONS',
                     'CARGO_PROFILE_TEST_OVERFLOW_CHECKS'):
            self.assertIn(name, M.ENV_KEYS)


if __name__ == '__main__':
    unittest.main()
