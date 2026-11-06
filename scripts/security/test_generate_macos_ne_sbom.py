#!/usr/bin/env python3
"""Inert source and CLI custody controls; no Cargo or network execution."""
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

SCRIPT = Path(__file__).with_name('generate-macos-ne-sbom.py')
spec = importlib.util.spec_from_file_location('ne_sbom', SCRIPT)
collector = importlib.util.module_from_spec(spec)
spec.loader.exec_module(collector)


class SourceFixture(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='aegis-b10-ne-sbom-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / 'tools/macos/aegis-network-extension').mkdir(parents=True)
        for name, data in {
            'Cargo.toml': '[workspace]\nmembers=[]\n',
            'Cargo.lock': '# root lock\n',
            'rust-toolchain.toml': '[toolchain]\nchannel="1.97.1"\n',
            'tools/macos/aegis-network-extension/Cargo.toml':
                '[package]\nname="aegis-network-extension"\nversion="0.1.0"\n'
                '[features]\napple=[]\nsfu-media-vp8=[]\nenrolled-quic=[]\n',
            'tools/macos/aegis-network-extension/Cargo.lock': '# NE lock\n',
            'third_party/h2/Cargo.toml': '[package]\nname="h2"\nversion="0.4.16"\n',
        }.items():
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(data)
        subprocess.run(['git', 'init', '-q', str(self.root)], check=True)
        subprocess.run(['git', '-C', str(self.root), 'add', '.'], check=True)
        subprocess.run(['git', '-C', str(self.root), '-c', 'user.name=QA',
                        '-c', 'user.email=qa@example.invalid', 'commit', '-qm', 'pin'], check=True)
        self.head = subprocess.check_output(['git', '-C', str(self.root), 'rev-parse', 'HEAD'],
                                            text=True).strip()

    def test_selected_cargo_inputs_bound_to_git(self):
        pins = collector.source_inputs(self.root, self.head)
        self.assertEqual(len(pins), 6)
        self.assertIn('third_party/h2/Cargo.toml', pins)
        self.assertIn('tools/macos/aegis-network-extension/Cargo.lock', pins)

    def test_dirty_manifest_refused(self):
        (self.root / 'tools/macos/aegis-network-extension/Cargo.toml').write_text('[package]\n')
        with self.assertRaisesRegex(collector.Refused, 'source_dirty'):
            collector.source_inputs(self.root, self.head)

    def test_missing_optional_feature_refused_even_when_committed(self):
        path = self.root / 'tools/macos/aegis-network-extension/Cargo.toml'
        path.write_text(path.read_text().replace('sfu-media-vp8=[]\n', ''))
        subprocess.run(['git', '-C', str(self.root), 'add', '.'], check=True)
        subprocess.run(['git', '-C', str(self.root), '-c', 'user.name=QA',
                        '-c', 'user.email=qa@example.invalid', 'commit', '-qm', 'remove feature'], check=True)
        head = subprocess.check_output(['git', '-C', str(self.root), 'rev-parse', 'HEAD'],
                                       text=True).strip()
        with self.assertRaisesRegex(collector.Refused, 'ne_feature_manifest_changed'):
            collector.source_inputs(self.root, head)

    def test_cli_is_feature_and_target_scoped(self):
        tool = self.root / 'cargo-cyclonedx'
        argv = collector.command(tool, self.root / collector.NE / 'Cargo.toml',
                                 'apple,sfu-media-vp8,enrolled-quic', 'aegis-ne-' + 'a' * 32)
        self.assertEqual(argv[1], 'cyclonedx')
        self.assertEqual(argv[argv.index('--target') + 1], 'aarch64-apple-darwin')
        self.assertEqual(argv[argv.index('--features') + 1],
                         'apple,sfu-media-vp8,enrolled-quic')
        self.assertIn('--all', argv)
        self.assertEqual(argv[argv.index('--override-filename') + 1],
                         'aegis-ne-' + 'a' * 32)
        self.assertEqual(argv[argv.index('--spec-version') + 1], '1.5')
        with self.assertRaisesRegex(collector.Refused, 'feature_or_output_changed'):
            collector.command(tool, self.root / collector.NE / 'Cargo.toml',
                              'all', 'aegis-ne-' + 'a' * 32)

    def test_tool_hash_and_version_are_both_required(self):
        tool = self.root / 'cargo-cyclonedx'
        tool.write_text('#!/bin/sh\necho cargo-cyclonedx-cyclonedx 0.5.9\n')
        tool.chmod(0o700)
        digest = hashlib.sha256(tool.read_bytes()).hexdigest()
        self.assertEqual(collector.tool_pin(tool, digest), 'cargo-cyclonedx-cyclonedx 0.5.9')
        with self.assertRaisesRegex(collector.Refused, 'tool_bytes_changed'):
            collector.tool_pin(tool, '0' * 64)
        tool.write_text('#!/bin/sh\necho cargo-cyclonedx-cyclonedx 0.5.8\n')
        with self.assertRaisesRegex(collector.Refused, 'tool_version_changed'):
            collector.tool_pin(tool, hashlib.sha256(tool.read_bytes()).hexdigest())

    def test_full_json_normalization_preserves_identity_fields(self):
        bom = {'bomFormat': 'CycloneDX', 'specVersion': '1.5',
               'serialNumber': 'urn:uuid:exact', 'metadata': {'timestamp': 'exact'},
               'components': [{'bom-ref': 'x', 'name': 'x'}]}
        canonical = collector.canonical_bom(json.dumps(bom).encode())
        self.assertEqual(json.loads(canonical), bom)
        with self.assertRaisesRegex(collector.Refused, 'bom_schema_or_components_missing'):
            collector.canonical_bom(json.dumps({**bom, 'components': []}).encode())


if __name__ == '__main__':
    unittest.main()
