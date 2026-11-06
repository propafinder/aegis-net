"""Closed native Stop diagnostics survive the coordinator's failed child call."""
import contextlib
import importlib.util
import io
from pathlib import Path
import stat
import subprocess
import sys
from types import SimpleNamespace
import unittest
from unittest import mock

SOURCE = Path(__file__).resolve().parents[1] / 'lib' / 'aegis_installer_auto_v2.py'
SPEC = importlib.util.spec_from_file_location('aegis_stop_diag_test', SOURCE)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
MARKER = 'AUTO_FINALIZED_STOP_DIAGNOSTIC phase=completed_quiescence errno=9'


class NativeStopDiagnostic(unittest.TestCase):
    def test_verified_stop_forwards_only_the_native_stop_failure(self):
        pointer = {'installed_binary': '/private/pinned/aegis-client',
                   'stage': '/private/pinned/stage',
                   'candidate_sha256': 'a' * 64, 'boot_id': 'boot'}
        seen = []

        def failed_native(argv, **kwargs):
            seen.append((argv, kwargs))
            if kwargs.get('diagnostic_stderr') is True:
                print(MARKER, file=sys.stderr)
            raise subprocess.CalledProcessError(1, argv)

        output = io.StringIO()
        with mock.patch.object(MODULE.os, 'open', return_value=11), \
             mock.patch.object(MODULE.os, 'fstat', return_value=SimpleNamespace(
                 st_mode=stat.S_IFREG | 0o755, st_uid=0, st_nlink=1)), \
             mock.patch.object(MODULE.os, 'close'), \
             mock.patch.object(MODULE, 'file_sha', return_value=(0, 'a' * 64)), \
             mock.patch.object(MODULE, 'current_boot', return_value='boot'), \
             mock.patch.object(MODULE, 'inspect_after_stop', side_effect=MODULE.Refused()), \
             mock.patch.object(MODULE, 'inspect_unsealed_after_stop', side_effect=MODULE.Refused()), \
             mock.patch.object(MODULE, 'call_output', side_effect=failed_native), \
             contextlib.redirect_stderr(output):
            with self.assertRaises(subprocess.CalledProcessError):
                MODULE.verified_stop(pointer)
        self.assertEqual(len(seen), 1)
        self.assertEqual(seen[0][0], [pointer['installed_binary'],
                                      'auto-stop-finalized', pointer['stage']])
        self.assertEqual(seen[0][1]['timeout'], 45)
        self.assertEqual(output.getvalue(), MARKER + '\n')

    def test_sealed_inspector_forwards_only_fixed_stopped_phase(self):
        record = {'schema':'aegis_auto_v2_stopped_stage_inspection_v1',
                  'stage':{'path':'/private/pinned/stage'},
                  'published_paths':{'current_verified':True},
                  'terminal':{'outcome':'finalized-stopped','boot_id':'boot',
                              'stop_terminal_sha256':'a'*64},
                  'main':{'stopped_verified':True,'no_live_lease_verified':True,
                          'fdstore_empty_verified':True},
                  'guardian':{'deny_verified':True,'fdstore_empty_verified':True}}
        with mock.patch.object(MODULE,'call_output',return_value=__import__('json').dumps(record).encode()) as call:
            MODULE.inspect_after_stop('/private/pinned/aegis-client',
                                      '/private/pinned/stage','boot')
        self.assertEqual(call.call_args.kwargs,
                         {'maximum':128*1024,'timeout':30,'diagnostic_stderr':True})

    def test_call_output_inherits_only_the_child_fixed_diagnostic(self):
        child = "import sys;sys.stderr.write(%r);sys.exit(1)" % (MARKER + '\n',)
        code = ("import importlib.util,sys;"
                "s=importlib.util.spec_from_file_location('coordinator',sys.argv[1]);"
                "m=importlib.util.module_from_spec(s);s.loader.exec_module(m);"
                "child=%r;"
                "\ntry:m.call_output([sys.executable,'-c',child],diagnostic_stderr=True)"
                "\nexcept m.Refused:pass\n" % (child,))
        result = subprocess.run([sys.executable, '-I', '-B', '-c', code, str(SOURCE)],
                                capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stderr.decode(), MARKER + '\n')
        self.assertEqual(result.stdout, b'')


if __name__ == '__main__':
    unittest.main()
