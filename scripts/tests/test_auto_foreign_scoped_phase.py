#!/usr/bin/env python3
"""Scoped PREROUTING receipt phases seen by every foreign-policy assessor.

The guardian installs the deny-only INPUT gate during capture registration
(scoped_prepare) and the ExecStartPre BIND writes BOUND later. The monitor,
the guardian BIND assessments and the device-guard helper all call
verified_owned_tables in between (r9 and r14 #36: FileNotFoundError on the
absent BOUND, sticky foreign_policy_drift). Only the exact prepared phase is
admitted, with the live host identity check.

Hermetic: every receipt path, nft, the ip readback, the boot id, the netns
and the interface index are test doubles, so CI may run this as root.
"""
import copy
import errno
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import types
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts/lib'))
import aegis_auto_foreign_policy as foreign
import aegis_auto_guard_policy as policy

BOOT_ID = '11111111-2222-3333-4444-555555555555'
SCOPED = ('INTENT', 'PREPARED', 'BOUND', 'ACTIVE', 'RETIRE_INTENT')
LOCAL = ('INTENT', 'BOUND', 'ACTIVE', 'RETIRE_INTENT')
REFUSED = policy.PolicyRefused
DRIFT = foreign.ForeignPolicyRefused
RULESET = {'nftables': [{'metainfo': {'json_schema_version': 1}},
                        {'table': {'family': 'ip', 'name': 'aegis_auto_redirect',
                                   'handle': 1}}]}
# nft keeps object handles across the later PREROUTING transaction.
HANDLES = {('table', None): 1, ('chain', 'input_gate'): 2, ('rule', 'input_gate', 0): 3,
           ('rule', 'input_gate', 1): 4, ('chain', 'prerouting'): 5,
           ('rule', 'prerouting', 0): 6}


def exact(message):
    return '^' + message + '$'


def binding():
    return {'stage_dev': 11, 'stage_ino': 12,
            'private_unit': 'aegis-auto@' + 'a' * 64 + '.service',
            'transaction_nonce': 'b' * 32, 'planned_generation': 'c' * 64,
            'boot_id': BOOT_ID, 'netns_ino': 42,
            'config_sha256_initial': 'd' * 64, 'config_semantic_sha256': 'e' * 64,
            'interface': 'aegisacp0', 'ifindex': 7,
            'listen_ipv4': '10.231.80.1', 'listen_port': 15080,
            'guard_policy_sha256': 'f' * 64}


def kernel(value, active, offset=0):
    rows = [{'metainfo': {'json_schema_version': 1}}]
    seen = {}
    for item in policy._scoped_expected(value, active=active):
        row = copy.deepcopy(item)
        kind, body = next(iter(row.items()))
        if kind == 'table':
            key = ('table', None)
        elif kind == 'chain':
            key = ('chain', body['name'])
        else:
            index = seen.get(body['chain'], 0)
            seen[body['chain']] = index + 1
            key = ('rule', body['chain'], index)
        body['handle'] = HANDLES[key] + offset
        rows.append(row)
    return {'nftables': rows}


class Host:
    """The host identity _scoped_binding(check_host=True) reads back."""

    def __init__(self):
        self.reset()

    def reset(self):
        self.boot_id = BOOT_ID
        self.netns = 42
        self.ifindex = {'aegisacp0': 7}
        self.addresses = [{'family': 'inet', 'local': '10.231.80.1', 'prefixlen': 24}]
        self.readbacks = 0

    def path(self, *parts):
        path = Path(*parts)
        if str(path) == '/proc/sys/kernel/random/boot_id':
            return types.SimpleNamespace(
                read_text=lambda encoding=None: self.boot_id + '\n')
        return path

    def os(self):
        host = self

        class HostOs:
            def __getattr__(self, name):
                return getattr(os, name)

            def stat(self, path, *args, **kwargs):
                if str(path) == '/proc/self/ns/net':
                    return types.SimpleNamespace(st_ino=host.netns)
                return os.stat(path, *args, **kwargs)
        return HostOs()

    def socket(self):
        def if_nametoindex(name):
            if name not in self.ifindex:
                raise OSError(errno.ENODEV, 'no such device')
            return self.ifindex[name]
        return types.SimpleNamespace(if_nametoindex=if_nametoindex)

    def subprocess(self):
        host = self

        def run(argv, **options):
            if list(argv[:6]) != [str(policy.SCOPED_IP), '-j', '-4', 'address', 'show',
                                  'dev'] or len(argv) != 7:
                raise AssertionError('unexpected host command')
            host.readbacks += 1
            rows = [{'ifindex': host.ifindex.get(argv[6]), 'ifname': argv[6],
                     'addr_info': copy.deepcopy(host.addresses)}]
            return subprocess.CompletedProcess(argv, 0, json.dumps(rows).encode(), b'')
        return types.SimpleNamespace(run=run, CompletedProcess=subprocess.CompletedProcess)


class ScopedPhases(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.binding = binding()
        self.table = kernel(self.binding, False)
        self.host = Host()
        self.check_host = []
        self.during_readback = None
        patches = [mock.patch.object(policy, 'SCOPED_PARENT', self.root)]
        patches += [mock.patch.object(policy, 'SCOPED_' + name,
                                      self.root / ('auto-redirect-' + name.lower() + '.json'))
                    for name in SCOPED]
        patches += [mock.patch.object(policy, 'LOCAL_' + name,
                                      self.root / ('auto-local-redirect-' + name.lower()
                                                   + '.json'))
                    for name in LOCAL]
        real_binding = policy._scoped_binding

        def recorded_binding(value, *, check_host=True):
            self.check_host.append(check_host)
            return real_binding(value, check_host=check_host)

        def nft(args, *, script=None, timeout=2.0):
            if args[:2] == ['-f', '-']:
                if b'prerouting' in script:
                    self.table = kernel(self.binding, True)
                return subprocess.CompletedProcess(args, 0, b'', b'')
            self.assertEqual(args, ['--json', '--handle', 'list', 'table', 'ip',
                                    'aegis_auto_redirect'])
            if self.during_readback is not None:
                self.during_readback()
            return subprocess.CompletedProcess(args, 0, json.dumps(self.table).encode(), b'')

        def read(path):
            # Same O_NOFOLLOW regular-file read as the product reader; only its
            # root-ownership check is not reproducible without root.
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
            try:
                return os.read(fd, 16385)
            finally:
                os.close(fd)

        def write(path, value):
            raw = policy._scoped_json(value)
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            try:
                os.write(fd, raw)
            finally:
                os.close(fd)
            return policy.hashlib.sha256(raw).hexdigest()

        patches += [
            mock.patch.object(policy, '_scoped_binding', side_effect=recorded_binding),
            mock.patch.object(policy, 'Path', side_effect=self.host.path),
            mock.patch.object(policy, 'os', self.host.os()),
            mock.patch.object(policy, 'socket', self.host.socket()),
            mock.patch.object(policy, 'subprocess', self.host.subprocess()),
            mock.patch.object(policy, '_scoped_nft', side_effect=nft),
            mock.patch.object(policy, '_scoped_bytes', side_effect=read),
            mock.patch.object(policy, '_scoped_write', side_effect=write),
            mock.patch.object(policy, '_scoped_absent', return_value=True),
            mock.patch.object(policy, '_local_absent', return_value=True)]
        for item in patches:
            item.start()
            self.addCleanup(item.stop)

    def assess(self):
        return foreign.verified_owned_tables(RULESET, self.root / 'device-guard.conf')

    def prepare(self):
        for name in SCOPED:
            path = getattr(policy, 'SCOPED_' + name)
            if path.exists() or path.is_symlink():
                path.unlink()
        self.table = kernel(self.binding, False)
        self.host.reset()
        policy.scoped_prepare(self.binding)
        self.assertFalse(policy.SCOPED_BOUND.exists() or policy.SCOPED_BOUND.is_symlink())
        self.check_host.clear()
        self.host.readbacks = 0

    def test_every_receipt_path_is_inside_the_temporary_directory(self):
        for prefix, names in (('SCOPED_', SCOPED), ('LOCAL_', LOCAL)):
            for name in names:
                self.assertEqual(getattr(policy, prefix + name).parent, self.root)
        self.assertEqual(policy.SCOPED_PARENT, self.root)

    def test_prepared_phase_before_bind_is_admitted_with_live_host_identity(self):
        # 1e917f0c: FileNotFoundError on auto-redirect-bound.json (r9, r14).
        self.prepare()
        self.assertEqual(self.assess(), {('ip', 'aegis_auto_redirect')})
        self.assertEqual(self.check_host, [True])
        self.assertEqual(self.host.readbacks, 1)

    def test_every_owned_phase_from_prepare_to_active_is_admitted(self):
        self.prepare()
        self.assertEqual(self.assess(), {('ip', 'aegis_auto_redirect')})
        policy.scoped_bind_invocation(self.binding, '1' * 32,
                                      deadline=time.monotonic() + 5.0)
        self.check_host.clear()
        self.assertEqual(self.assess(), {('ip', 'aegis_auto_redirect')})
        self.assertEqual(self.check_host, [True])
        policy.scoped_activate(self.binding, '1' * 32)
        self.check_host.clear()
        self.assertEqual(self.assess(), {('ip', 'aegis_auto_redirect')})
        self.assertEqual(self.check_host, [True])

    def test_prepared_phase_refuses_changed_host_identity(self):
        cases = (
            ('boot', lambda host: setattr(host, 'boot_id', BOOT_ID[:-1] + '6'),
             'scoped host identity changed'),
            ('netns', lambda host: setattr(host, 'netns', 43),
             'scoped host identity changed'),
            ('ifindex', lambda host: host.ifindex.update(aegisacp0=8),
             'scoped host identity changed'),
            ('primary_ipv4', lambda host: host.addresses[0].update(local='10.231.80.2'),
             'scoped interface address changed'),
            ('second_primary', lambda host: host.addresses.append(
                {'family': 'inet', 'local': '10.231.81.1', 'prefixlen': 24}),
             'scoped interface address changed'))
        for label, change, message in cases:
            with self.subTest(change=label):
                self.prepare()
                change(self.host)
                with self.assertRaisesRegex(REFUSED, exact(message)):
                    self.assess()
                self.assertEqual(self.check_host, [True])
        # A secondary address is not the REDIRECT target and stays admitted.
        self.prepare()
        self.host.addresses.append({'family': 'inet', 'local': '10.231.81.1',
                                    'prefixlen': 24, 'secondary': True})
        self.assertEqual(self.assess(), {('ip', 'aegis_auto_redirect')})

    def test_prepared_only_retire_intent_is_admitted_only_exactly(self):
        self.prepare()
        intent = policy._scoped_read(policy.SCOPED_INTENT)
        prepared = policy._scoped_read(policy.SCOPED_PREPARED)
        record = {'schema': 'aegis_auto_scoped_redirect_retire_intent_v1',
                  'intent_sha256': policy._scoped_hash(intent),
                  'prepared_sha256': policy._scoped_hash(prepared),
                  'bound_sha256': None, 'active_sha256': None,
                  'prior_policy': prepared['policy'], 'reboot': False}
        policy._scoped_write(policy.SCOPED_RETIRE_INTENT, record)
        self.assertEqual(self.assess(), {('ip', 'aegis_auto_redirect')})
        for key, value in (('bound_sha256', '0' * 64), ('active_sha256', '0' * 64),
                           ('reboot', True), ('prior_policy', None),
                           ('intent_sha256', '0' * 64), ('prepared_sha256', '0' * 64)):
            with self.subTest(field=key):
                policy.SCOPED_RETIRE_INTENT.unlink()
                policy._scoped_write(policy.SCOPED_RETIRE_INTENT, {**record, key: value})
                with self.assertRaisesRegex(DRIFT, exact('scoped prepared retire intent changed')):
                    self.assess()

    def test_prepared_gate_projection_must_be_exact(self):
        self.prepare()
        accept = next(i for i, row in enumerate(self.table['nftables'])
                      if 'rule' in row and {'accept': None} in row['rule']['expr'])
        changed = copy.deepcopy(self.table)
        changed['nftables'][accept]['rule']['expr'] = [
            item for item in changed['nftables'][accept]['rule']['expr']
            if not ('match' in item and item['match']['left'] == {'ct': {'key': 'mark'}})]
        self.table = changed
        with self.assertRaisesRegex(REFUSED, exact('scoped kernel policy differs from renderer')):
            self.assess()
        # A full PREROUTING table without BOUND is never the prepared phase.
        self.table = kernel(self.binding, True)
        with self.assertRaisesRegex(REFUSED, exact('scoped kernel policy differs from renderer')):
            self.assess()
        # Handles that differ from the PREPARED receipt are another gate.
        self.table = kernel(self.binding, False, offset=100)
        with self.assertRaisesRegex(REFUSED, exact('scoped input gate changed')):
            self.assess()

    def test_other_receipt_combinations_refuse(self):
        self.prepare()
        policy.SCOPED_PREPARED.unlink()
        with self.assertRaisesRegex(FileNotFoundError, 'auto-redirect-prepared\\.json'):
            self.assess()
        self.prepare()
        policy._scoped_write(policy.SCOPED_ACTIVE,
                             {'schema': 'aegis_auto_scoped_redirect_active_v1'})
        with self.assertRaisesRegex(DRIFT, exact('scoped active receipt without bound owner')):
            self.assess()
        self.prepare()
        policy.SCOPED_ACTIVE.symlink_to(self.root / 'absent-active.json')
        with self.assertRaisesRegex(DRIFT, exact('scoped active receipt without bound owner')):
            self.assess()
        for dangling in (False, True):
            with self.subTest(bound_symlink_dangling=dangling):
                self.prepare()
                target = self.root / 'elsewhere.json'
                if target.exists():
                    target.unlink()
                if not dangling:
                    policy._scoped_write(target, {'schema': 'aegis_auto_scoped_redirect_bound_v1'})
                policy.SCOPED_BOUND.symlink_to(target)
                with self.assertRaises(OSError) as raised:
                    self.assess()
                self.assertEqual(raised.exception.errno, errno.ELOOP)
                policy.SCOPED_BOUND.unlink()
        self.prepare()
        policy.SCOPED_INTENT.unlink()
        with self.assertRaisesRegex(FileNotFoundError, 'auto-redirect-intent\\.json'):
            self.assess()
        self.prepare()
        other = dict(self.binding, transaction_nonce='9' * 32)
        policy.SCOPED_INTENT.unlink()
        policy._scoped_write(policy.SCOPED_INTENT, policy._scoped_intent(other))
        with self.assertRaisesRegex(REFUSED, exact('scoped prepared receipt changed')):
            self.assess()
        self.prepare()
        intent = policy._scoped_read(policy.SCOPED_INTENT)
        policy.SCOPED_INTENT.unlink()
        policy._scoped_write(policy.SCOPED_INTENT,
                             dict(intent, conntrack_mark=intent['conntrack_mark'] ^ 1))
        with self.assertRaisesRegex(DRIFT, exact('scoped prepared intent changed')):
            self.assess()
        self.prepare()
        policy.SCOPED_INTENT.unlink()
        policy._scoped_write(policy.SCOPED_INTENT, dict(intent, binding=dict(
            intent['binding'], extra=1)))
        with self.assertRaisesRegex(REFUSED, exact('scoped binding fields invalid')):
            self.assess()
        self.prepare()
        policy.SCOPED_INTENT.unlink()
        policy._scoped_write(policy.SCOPED_INTENT, dict(intent, binding=None))
        with self.assertRaisesRegex(DRIFT, exact('scoped prepared intent invalid')):
            self.assess()

    def test_active_receipt_published_during_assessment_refuses(self):
        self.prepare()

        def publish():
            self.during_readback = None
            policy._scoped_write(policy.SCOPED_ACTIVE,
                                 {'schema': 'aegis_auto_scoped_redirect_active_v1'})
        self.during_readback = publish
        with self.assertRaisesRegex(DRIFT, exact('scoped prepared phase changed')):
            self.assess()


if __name__ == '__main__':
    unittest.main()
