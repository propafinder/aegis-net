#!/usr/bin/env python3
"""Stage identity must be proven before the whole-ZIP parser can read it."""
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock


SOURCE = Path(__file__).with_name('inventory-macos-bundle.py')
SPEC = importlib.util.spec_from_file_location('inventory_macos_bundle', SOURCE)
inventory = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(inventory)


class StagedPreinstallScope(unittest.TestCase):
    def test_exact_stage_reaches_archive_and_mutants_refuse_before_archive(self):
        with tempfile.TemporaryDirectory(dir='/private/tmp') as temp:
            root = Path(temp)
            source = 'a' * 40
            # No source or bundle copy is needed for this pre-archive gate.
            run = root / 'artifacts' / 'runs' / ('v44-test-' + source[:12])
            receipt_path = root / 'artifacts' / 'receipts' / (run.name + '.json')
            receipt_path.parent.mkdir(parents=True)
            bundle = run / 'bundle' / 'AEGIS.app'
            archive = run / 'stapled.zip'
            row = {'commit': source, 'source_dirty': False,
                   'binaries_source': 'build-stage', 'stapled_zip_sha256': 'b' * 64,
                   'stapled_zip': str(archive), 'notary_status': 'Accepted',
                   'run_dir': str(run), 'installed': False,
                   'stages': [{'stage': stage, 'status': 'ok'} for stage in
                              ('build', 'assemble', 'sign', 'verify', 'zip',
                               'notarize', 'staple', 'assess')]}
            def write_receipt(value):
                receipt_path.write_text(json.dumps(value))
                receipt_path.chmod(0o600)
                return hashlib.sha256(receipt_path.read_bytes()).hexdigest()
            original_open = inventory.opened_file
            def stop_at_archive(path, stack, **kw):
                if path == archive:
                    raise AssertionError('archive_open_reached')
                return original_open(path, stack, **kw)
            with mock.patch.object(inventory, 'opened_file', side_effect=stop_at_archive):
                pin = write_receipt(row)
                with self.assertRaisesRegex(AssertionError, 'archive_open_reached'):
                    inventory.inspect(bundle, archive, 'b' * 64,
                                      receipt_path, pin, source, 'staged-preinstall')
                for wrong_bundle, wrong_archive, installed in (
                    (run / 'foreign.app', archive, False),
                    (bundle, run / 'other.zip', False),
                    (bundle, archive, True),
                ):
                    changed = dict(row, installed=installed)
                    pin = write_receipt(changed)
                    with self.assertRaisesRegex(ValueError,
                                                'staged_preinstall_receipt_and_bundle_path'):
                        inventory.inspect(wrong_bundle, wrong_archive, 'b' * 64,
                                          receipt_path, pin, source,
                                          'staged-preinstall')


if __name__ == '__main__':
    unittest.main()
