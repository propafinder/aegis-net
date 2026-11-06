#!/usr/bin/env python3
import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

ROOT=Path(__file__).resolve().parents[1]
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
policy=load('profile_policy',ROOT/'scripts/security/check-license-profiles.py')
notices=load('notices',ROOT/'scripts/generate-third-party-notices.py')


class ShippingCoverage(unittest.TestCase):
    def test_metadata_superset_keeps_normal_build_edges_and_refuses_missing_nodes(self):
        metadata = {
            'workspace_members': ['root'],
            'packages': [{'id': key, 'name': key} for key in ('root', 'normal', 'build', 'dev')],
            'resolve': {'nodes': [
                {'id': 'root', 'deps': [
                    {'pkg': 'normal', 'dep_kinds': [{'kind': None}]},
                    {'pkg': 'build', 'dep_kinds': [{'kind': 'build'}]},
                    {'pkg': 'dev', 'dep_kinds': [{'kind': 'dev'}]},
                ]},
                {'id': 'normal', 'deps': []}, {'id': 'build', 'deps': []},
                {'id': 'dev', 'deps': []},
            ]},
        }
        self.assertEqual({p['id'] for p in notices.normal_build_metadata_packages(metadata, 'root')},
                         {'root', 'normal', 'build'})
        metadata['resolve']['nodes'] = [row for row in metadata['resolve']['nodes']
                                        if row['id'] != 'build']
        with self.assertRaisesRegex(RuntimeError, 'package or resolve node missing'):
            notices.normal_build_metadata_packages(metadata, 'root')

    def test_optional_vp8_is_checked_on_both_macos_architectures(self):
        rows = policy.profiles(ROOT)
        selected = {(name, target, features) for name, _, target, features in rows
                    if features == 'apple,sfu-media-vp8'}
        self.assertEqual(selected, {
            ('macos-arm64-extension-vp8', 'aarch64-apple-darwin', 'apple,sfu-media-vp8'),
            ('macos-x64-extension-vp8', 'x86_64-apple-darwin', 'apple,sfu-media-vp8'),
        })
        self.assertEqual(len(rows), 10)

    def test_policy_covers_every_actual_notice_graph(self):
        with mock.patch.object(notices,'add_scope')as scope:
            notices.render()
        expected=[(call.args[1],call.args[2],call.args[3],call.args[5])for call in scope.call_args_list]
        self.assertEqual(policy.profiles(ROOT),expected)

    def test_every_profile_is_offline_locked_and_failures_do_not_skip_the_rest(self):
        calls=[]
        def run(argv,**kwargs):
            calls.append(argv);self.assertLessEqual(kwargs['timeout'],180)
            return subprocess.CompletedProcess(argv,4 if len(calls)==2 else 0)
        with tempfile.TemporaryDirectory()as temp:
            rows=policy.check_profiles(ROOT,Path(temp),runner=run)
        self.assertEqual(len(calls),10);self.assertEqual(rows[1]['rc'],4)
        self.assertTrue(all(v['executed']for v in rows))
        for argv in calls:
            self.assertIn('--offline',argv);self.assertIn('--locked',argv)
            self.assertEqual(argv[-4:],['check','licenses','bans','sources'])
            self.assertEqual(argv[argv.index('--config')+1],str(ROOT/'deny.toml'))

    def test_timeout_is_a_failure_and_remaining_profiles_still_execute(self):
        calls=[]
        def run(argv,**kwargs):
            calls.append(argv)
            if len(calls)==1:raise subprocess.TimeoutExpired(argv,kwargs['timeout'])
            return subprocess.CompletedProcess(argv,0)
        with tempfile.TemporaryDirectory()as temp:
            rows=policy.check_profiles(ROOT,Path(temp),runner=run)
        self.assertEqual(rows[0]['rc'],124);self.assertEqual(len(rows),10)
        self.assertEqual(len(calls),10)

    def test_exhausted_batch_deadline_never_counts_unexecuted_profiles_as_pass(self):
        run=mock.Mock()
        with tempfile.TemporaryDirectory()as temp,mock.patch.object(policy.time,'monotonic',side_effect=[0]+[601]*10):
            rows=policy.check_profiles(ROOT,Path(temp),runner=run)
        run.assert_not_called();self.assertEqual(len(rows),10)
        self.assertTrue(all(v['rc']==124 and not v['executed']for v in rows))


if __name__=='__main__':unittest.main()
