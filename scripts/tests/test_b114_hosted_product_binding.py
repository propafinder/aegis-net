#!/usr/bin/env python3
"""Source-only controls for the hosted final-product SHA binding."""

import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

import sys

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / 'scripts/qa'))
import b114_hosted_full13_contract as contract
import b114_hosted_x86_firstcold as firstcold


S = subprocess.check_output(['git', '-C', str(REPO), 'rev-parse', 'HEAD'],
                            text=True, timeout=10).strip()
OPERATOR_MANIFEST = '2' * 64
PRODUCT_MANIFEST = '3' * 64


def private_record(path, row):
    path.write_text(json.dumps(row, sort_keys=True) + '\n')
    path.chmod(0o600)
    return contract.sha256(path)


class ProductBindingControls(unittest.TestCase):
    def setUp(self):
        contract.PRODUCT_SOURCE = contract.PRODUCT_SOURCE_ANCHOR
        contract._PRODUCT_SOURCE_BOUND = False
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.owner = os.geteuid()

    def tearDown(self):
        contract.PRODUCT_SOURCE = contract.PRODUCT_SOURCE_ANCHOR
        contract._PRODUCT_SOURCE_BOUND = False

    def records(self, *, artifact_source=S,
                binding_product_manifest=PRODUCT_MANIFEST):
        artifact = {
            'schema': 'aegis_b114_hosted_x86_artifact_review_v1',
            'source_commit': artifact_source,
            'source_manifest_sha256': PRODUCT_MANIFEST,
            'scope': 'qemu_guest_only',
            'platform': contract.PLATFORM,
            'arch': 'x86_64',
            'independent_review_pass': True,
            'native_binary_executed_in_guest': True,
            'client_elf_sha256': '4' * 64,
            'server_elf_sha256': '5' * 64,
            'package_sha256': '6' * 64,
            'admin_tar_sha256': '7' * 64,
        }
        artifact_sha = private_record(self.root / 'artifact.json', artifact)
        binding = {
            'schema': 'aegis_b114_hosted_x86_product_binding_v1',
            'product_source_commit': S,
            'operator_source_commit': S,
            'operator_source_manifest_sha256': OPERATOR_MANIFEST,
            'product_source_manifest_sha256': binding_product_manifest,
            'product_artifact_review_sha256': artifact_sha,
        }
        binding_path = self.root / 'binding.json'
        binding_sha = private_record(binding_path, binding)
        review = {
            'schema': 'aegis_b114_hosted_x86_product_binding_review_v1',
            'binding_sha256': binding_sha,
            'product_source_commit': S,
            'product_source_manifest_sha256': binding_product_manifest,
            'product_artifact_review_sha256': artifact_sha,
            'source_artifact_parity_verified': True,
            'independent_review_pass': True,
        }
        review_path = self.root / 'review.json'
        review_sha = private_record(review_path, review)
        return {
            'product_binding_path': str(binding_path),
            'product_binding_sha256': binding_sha,
            'product_binding': binding,
            'product_binding_review_path': str(review_path),
            'product_binding_review_sha256': review_sha,
            'product_binding_review': review,
            'product_b_artifact_sha256': artifact_sha,
            'product_b_artifact': artifact,
            'b_artifact_identities_sha256': '8' * 64,
        }

    def bind(self, inputs):
        return contract.bind_product_source(
            REPO, inputs, self.owner, S, OPERATOR_MANIFEST)

    def test_final_source_equals_operator_and_reaches_b_receipts(self):
        inputs = self.records()
        target = self.bind(inputs)
        self.assertEqual(target, S)
        subprocess.run(['git', '-C', str(REPO), 'merge-base', '--is-ancestor',
                        contract.PRODUCT_SOURCE_ANCHOR, S],
                       check=True, timeout=10)
        subprocess.run(['git', '-C', str(REPO), 'merge-base', '--is-ancestor',
                        S, S], check=True, timeout=10)
        artifact = contract.x86_artifact(inputs['product_b_artifact'], 'b')
        pins = firstcold.b_pins(inputs, artifact)
        self.assertEqual(json.loads(pins)['product_source'], S)
        self.assertEqual(json.loads(pins)['artifact_review_sha256'],
                         inputs['product_b_artifact_sha256'])

    def test_old_product_artifact_cannot_claim_final_source(self):
        inputs = self.records(artifact_source=contract.PRODUCT_SOURCE_ANCHOR)
        with self.assertRaisesRegex(ValueError,
                                    'final_product_source_artifact_parity_missing'):
            self.bind(inputs)

    def test_wrong_independent_review_sha_is_refused(self):
        inputs = self.records()
        inputs['product_binding_review_sha256'] = '9' * 64
        with self.assertRaisesRegex(ValueError, 'private_input_digest_changed'):
            self.bind(inputs)

    def test_wrong_product_manifest_is_refused(self):
        inputs = self.records(binding_product_manifest='8' * 64)
        with self.assertRaisesRegex(ValueError,
                                    'final_product_source_artifact_parity_missing'):
            self.bind(inputs)

    def test_b_artifact_admission_requires_prior_binding(self):
        inputs = self.records()
        with self.assertRaisesRegex(ValueError,
                                    'final_product_source_binding_required'):
            contract.x86_artifact(inputs['product_b_artifact'], 'b')


if __name__ == '__main__':
    unittest.main()
