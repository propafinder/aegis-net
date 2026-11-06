"""Fixed reload diagnostic protocol; no host or package actions."""
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest import mock

SOURCE = Path(__file__).resolve().parents[1] / 'lib/aegis_installer_auto_v2.py'
SPEC = importlib.util.spec_from_file_location('aegis_auto_v2_reload_diag', SOURCE)
AUTO = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(AUTO)


class Worker:
    stdin = io.BytesIO()
    def poll(self):
        return None


class ReloadDiagnosticTests(unittest.TestCase):
    def failure(self, response, words, phase):
        with mock.patch.object(AUTO, 'fixed_lines', return_value=json.dumps(response).encode()+b'\n'):
            with self.assertRaises(AUTO.Refused) as caught:
                AUTO.worker_phase(Worker(), words, time.monotonic(), phase=phase)
        return caught.exception

    def test_closed_label_only_for_exact_reload_phase(self):
        label = 'reload_second_pid1_final'
        response = {'status':'error','reason':'phase_refused','reload_failure':label}
        error = self.failure(response, ['reload-service-policy'], 'reload_policy')
        self.assertEqual(error.reload_failure, label)
        for words, phase in ((['reload-service-policy'],'publish_policy'),
                             (['publish-service-policy'],'reload_policy')):
            error = self.failure(response, words, phase)
            self.assertFalse(hasattr(error, 'reload_failure'))

    def test_unknown_or_extra_data_rejected(self):
        for label in ('reload_secret', 'reload_first_pid1_final:secret', 7):
            error = self.failure({'status':'error','reason':'phase_refused',
                                  'reload_failure':label},
                                 ['reload-service-policy'], 'reload_policy')
            self.assertFalse(hasattr(error, 'reload_failure'))
        error = self.failure({'status':'error','reason':'phase_refused',
                              'reload_failure':'reload_worker_after','extra':'secret'},
                             ['reload-service-policy'], 'reload_policy')
        self.assertFalse(hasattr(error, 'reload_failure'))

    def test_failure_receipt_contains_only_closed_label(self):
        with tempfile.TemporaryDirectory() as folder:
            fd = os.open(folder, os.O_RDONLY | os.O_DIRECTORY)
            worker = Worker()
            progress = {'phase':'reload_policy','worker':worker,
                        'worker_started':time.monotonic()}
            error = AUTO.Refused()
            error.reload_failure = 'reload_native_fixed_command'
            with mock.patch.object(AUTO, 'control_directory', return_value=fd):
                AUTO.record_failure(progress, error)
            files = list(Path(folder).glob('failure-*.json'))
            self.assertEqual(len(files), 1)
            value = json.loads(files[0].read_text())
            self.assertEqual(value['reload_failure'], 'reload_native_fixed_command')
            self.assertEqual(value['phase'], 'reload_policy')
            self.assertEqual(value['reason'], 'refused')
            self.assertNotIn('diagnostic', value)


if __name__ == '__main__':
    unittest.main()
