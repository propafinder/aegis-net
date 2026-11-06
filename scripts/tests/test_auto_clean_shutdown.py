#!/usr/bin/env python3
"""Design B+ (r20): shutdown-aware classification of a foreign-policy refusal.

Replaces the retired r19 one-use clean-shutdown handoff tests. Real systemctl
and nft output strings come from readbacks captured in disposable systemd
252/255 containers (fixtures/README.md). Nothing here needs root, a network,
a lock or PID1; the Linux root kernel stand at the end is opt-in.
"""
import ast
import contextlib
import errno
import fnmatch
import gzip
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import types
import unittest
from unittest import mock
import uuid

HERE = Path(__file__).resolve().parent
LIB = HERE.parent / 'lib'
SCRIPTS = HERE.parent
REPO = SCRIPTS.parent
sys.path.insert(0, str(LIB))
sys.path.insert(0, str(HERE))
import aegis_auto_foreign_monitor as monitor  # noqa: E402
import aegis_auto_foreign_policy as policy  # noqa: E402
import auto_guard_render_harness as harness  # noqa: E402


def fixture(name):
    with gzip.open(HERE / 'fixtures' / name, 'rb') as stream:
        return json.loads(stream.read().decode('utf-8'))


NFT = fixture('auto_shutdown_nft_readbacks_r26.json.gz')
PID1 = fixture('auto_shutdown_pid1_readbacks.json.gz')
TARGETS = ('exit.target', 'halt.target', 'kexec.target', 'poweroff.target',
           'reboot.target', 'soft-reboot.target')
STOPPING = 'SystemState=stopping\n'
# Distinct real classification sequences the fixture must keep (see README).
MIN_CLASSIFICATIONS = 20
MIN_VERDICTS = {'confirmed': 5, 'denied': 3}


def start(test, target, attribute, **kwargs):
    patcher = mock.patch.object(target, attribute, **kwargs)
    value = patcher.start()
    test.addCleanup(patcher.stop)
    return value


def items(raw):
    return monitor._items(json.loads(raw))


@contextlib.contextmanager
def cgroupfs(live):
    """Fake cgroupfs for _cgroup_id and live_client_grant: path -> id while live."""
    real_stat, real_isdir = os.stat, os.path.isdir
    prefix = '/sys/fs/cgroup/'

    def stat(path, *args, **kwargs):
        if isinstance(path, str) and path.startswith(prefix):
            relative = os.path.normpath(path)[len(prefix):]  # as the kernel resolves it
            if relative in live:
                return types.SimpleNamespace(st_ino=live[relative])
            raise FileNotFoundError(errno.ENOENT, 'cgroup removed', path)
        return real_stat(path, *args, **kwargs)

    def isdir(path):
        if isinstance(path, str) and path.startswith(prefix):
            return path[len(prefix):] in live
        return real_isdir(path)
    with mock.patch.object(monitor.os, 'stat', stat), \
            mock.patch.object(monitor.os.path, 'isdir', isdir):
        yield


class FakePID1:
    """systemctl answers as PID1 gives them; list-jobs applies the patterns."""

    def __init__(self, state, jobs='', active=(), states=None, fail=None, raw_jobs=False):
        self.state, self.jobs, self.active = state, jobs, set(active)
        self.states = list(states) if states else None
        self.fail, self.raw_jobs, self.calls = fail, raw_jobs, []

    def __call__(self, *argv):
        self.calls.append(argv)
        if self.fail is not None and self.fail(argv):
            raise policy.ForeignPolicyRefused('PID1 shutdown readback unavailable')
        if argv == ('show', '-p', 'SystemState'):
            if self.states:
                return self.states.pop(0) if len(self.states) > 1 else self.states[0]
            return self.state
        if argv[0] == 'list-jobs':
            if self.raw_jobs:
                return self.jobs
            patterns = argv[argv.index('--') + 1:]
            rows = [line for line in self.jobs.splitlines() if len(line.split()) > 1 and
                    any(fnmatch.fnmatchcase(line.split()[1], p) for p in patterns)]
            return ''.join(row + '\n' for row in rows)
        if argv[0] == 'show' and argv[-4:] == ('-p', 'Id', '-p', 'ActiveState'):
            return '\n\n'.join('Id=%s\nActiveState=%s' % (
                target, 'active' if target in self.active else 'inactive')
                for target in argv[1:-4]) + '\n'
        raise AssertionError(argv)


def verdict(read, exe=False):
    with mock.patch.object(monitor, '_pid1_read', read), \
            mock.patch.object(monitor, '_pid1_exe_is_shutdown', return_value=exe):
        return monitor.shutdown_verdict()


class ShutdownVerdict(unittest.TestCase):
    def test_real_252_255_classifications_replay_exactly(self):
        """Every PID1 readback sequence the monitor read in the container rows."""
        rows = PID1['classifications']
        self.assertGreaterEqual(len(rows), MIN_CLASSIFICATIONS)
        seen = {}
        for row in rows:
            reads = [(tuple(argv), out) for argv, out in row['reads']]

            def replay(*argv):
                self.assertTrue(reads, (row['run'], argv))
                expected, out = reads.pop(0)
                self.assertEqual(expected, argv, row['run'])
                if out is None:
                    raise policy.ForeignPolicyRefused('PID1 shutdown readback unavailable')
                return out
            with self.subTest(run=row['run'], index=row['index']):
                self.assertEqual(verdict(replay), row['verdict'])
                self.assertEqual(reads, [])
            seen.setdefault((row['systemd'], row['verdict']), 0)
            seen[(row['systemd'], row['verdict'])] += 1
        for version in (252, 255):
            for result in MIN_VERDICTS:
                self.assertGreaterEqual(seen.get((version, result), 0), MIN_VERDICTS[result],
                                        (version, result))

    def test_real_unfiltered_252_255_listings_through_the_pattern_filter(self):
        """Every r2 list-jobs listing, as systemctl filters it for the six targets."""
        rows = PID1['unfiltered']
        self.assertGreater(len(rows), 100)
        counted = {'confirmed': 0, 'denied': 0}
        for row in rows:
            terminal = [line.split()[1] for line in row['list_jobs'].splitlines()
                        if len(line.split()) == 4 and line.split()[2] == 'start' and
                        line.split()[1] in monitor.TERMINAL_TARGETS]
            other = [line for line in row['list_jobs'].splitlines()
                     if len(line.split()) == 4 and line.split()[1] in
                     monitor.NONTERMINAL_SHUTDOWN_TARGETS]
            result = verdict(FakePID1(row['system_state'], row['list_jobs']))
            with self.subTest(run=row['run'], label=row['label']):
                if row['system_state'] == STOPPING and len(terminal) == 1 and not other:
                    self.assertEqual(result, 'confirmed')
                elif row['system_state'] in ('SystemState=running\n', 'SystemState=degraded\n',
                                             'SystemState=starting\n'):
                    self.assertEqual(result, 'denied')
                elif row['system_state'] == STOPPING:
                    self.assertEqual(result, 'denied')
            counted[result] = counted.get(result, 0) + 1
        self.assertGreater(counted['confirmed'], 50)
        self.assertGreaterEqual(counted['denied'], 3)

    def test_listing_far_beyond_the_bound_is_filtered_by_pid1(self):
        """Hundreds of stop jobs with long names: only the six targets are read."""
        long = ''.join('%d systemd-cryptsetup@luks\\x2d%s.service stop waiting\n'
                       % (1000 + index, uuid.UUID(int=index).hex * 3) for index in range(900))
        listing = long + '715 reboot.target start waiting\n440 shutdown.target start waiting\n'
        self.assertGreater(len(listing), 1 << 17)
        fake = FakePID1(STOPPING, listing)
        self.assertEqual(verdict(fake), 'confirmed')
        jobs = [argv for argv in fake.calls if argv[0] == 'list-jobs']
        self.assertEqual(jobs, [('list-jobs', '--no-legend', '--plain', '--full', '--no-pager',
                                 '--') + TARGETS])
        # Unfiltered, the same listing exceeds the readback bound and stays unknown.
        with mock.patch.object(monitor.subprocess, 'run', return_value=subprocess.CompletedProcess(
                (), 0, listing.encode(), b'')):
            with self.assertRaises(policy.ForeignPolicyRefused):
                monitor._pid1_read('list-jobs')

    def test_states(self):
        for state, want in (('running', 'denied'), ('degraded', 'denied'), ('maintenance', 'denied'),
                            ('starting', 'denied'), ('initializing', 'denied'),
                            ('offline', 'unknown'), ('unknown', 'unknown'), ('bogus', 'unknown'),
                            ('', 'unknown')):
            with self.subTest(state=state):
                self.assertEqual(verdict(FakePID1('SystemState=%s\n' % state,
                                                  '7 reboot.target start waiting\n')), want)

    def test_terminal_shapes(self):
        job = '715 reboot.target start waiting\n440 shutdown.target start waiting\n'
        self.assertEqual(verdict(FakePID1(STOPPING, job)), 'confirmed')
        for target in ('poweroff.target', 'halt.target', 'kexec.target'):
            self.assertEqual(verdict(FakePID1(STOPPING, '7 %s start running\n' % target)),
                             'confirmed', target)
        # SuccessAction=reboot-force: the reboot.target job completed before exec.
        self.assertEqual(verdict(FakePID1(STOPPING, '', active={'reboot.target'})), 'confirmed')
        # cancelled or failed terminal job: stopping, nothing pending or reached
        self.assertEqual(verdict(FakePID1(STOPPING, '440 shutdown.target start waiting\n')), 'denied')
        self.assertEqual(verdict(FakePID1(STOPPING, '')), 'denied')
        # soft-reboot and exit are never terminal, pending or reached
        for target in ('soft-reboot.target', 'exit.target'):
            self.assertEqual(verdict(FakePID1(STOPPING, '9 %s start waiting\n' % target)), 'denied')
            self.assertEqual(verdict(FakePID1(STOPPING, job, active={target})), 'denied')
        # two terminal targets, or a non-start job only
        self.assertEqual(verdict(FakePID1(STOPPING, job + '716 poweroff.target start waiting\n')),
                         'denied')
        self.assertEqual(verdict(FakePID1(STOPPING, job, active={'poweroff.target'})), 'denied')
        self.assertEqual(verdict(FakePID1(STOPPING, '715 reboot.target stop waiting\n')), 'denied')

    def test_malformed_or_unavailable_readbacks_are_unknown(self):
        for jobs in ('715 reboot.target start\n', '715 reboot.target start waiting extra\n',
                     'x reboot.target start waiting\n', '0 reboot.target start waiting\n',
                     '7 reboot.target start waiting\n7 poweroff.target stop waiting\n',
                     '7 reboot.target start waiting\n8 reboot.target start waiting\n',
                     '7 reboot.target start blocked\n', '7 foreign.service start waiting\n',
                     '٧ reboot.target start waiting\n'):
            with self.subTest(jobs=jobs):
                self.assertEqual(verdict(FakePID1(STOPPING, jobs, raw_jobs=True)), 'unknown')
        for fail in (lambda argv: argv[0] == 'list-jobs',
                     lambda argv: argv == ('show', '-p', 'SystemState'),
                     lambda argv: argv[-1] == 'ActiveState'):
            self.assertEqual(verdict(FakePID1(STOPPING, '7 reboot.target start waiting\n',
                                              fail=fail)), 'unknown')
        for state in ('SystemState=stopping', 'SystemState=stopping\nX=1\n', 'stopping\n'):
            self.assertEqual(verdict(FakePID1(state, '7 reboot.target start waiting\n')), 'unknown')
        # PID1 moved on between the first and the last read
        self.assertEqual(verdict(FakePID1(STOPPING, '7 reboot.target start waiting\n',
                                          states=[STOPPING, 'SystemState=running\n'])), 'unknown')

        def targets(*argv):
            if argv[0] == 'show' and argv[-1] == 'ActiveState':
                return 'Id=reboot.target\nActiveState=inactive\n'
            return FakePID1(STOPPING, '7 reboot.target start waiting\n')(*argv)
        self.assertEqual(verdict(targets), 'unknown')

        def broken(*argv):
            raise subprocess.TimeoutExpired(argv, monitor.PID1_READ_SECONDS)
        self.assertEqual(verdict(broken), 'unknown')
        self.assertEqual(verdict(lambda *argv: (_ for _ in ()).throw(KeyError('x'))), 'unknown')

    def test_systemd_shutdown_exe_needs_no_read(self):
        def boom(*argv):
            raise AssertionError('no PID1 read after exec')
        self.assertEqual(verdict(boom, exe=True), 'confirmed')
        for target, want in (('/usr/lib/systemd/systemd-shutdown', True),
                             ('/lib/systemd/systemd-shutdown', True),
                             ('/usr/lib/systemd/systemd', False)):
            with mock.patch.object(monitor.os, 'readlink', return_value=target):
                self.assertIs(monitor._pid1_exe_is_shutdown(), want)
        with mock.patch.object(monitor.os, 'readlink', side_effect=PermissionError()):
            self.assertIs(monitor._pid1_exe_is_shutdown(), False)

    def test_pid1_read_is_bounded_minimal_and_read_only(self):
        calls = []

        def run(argv, **kwargs):
            calls.append((argv, kwargs))
            return subprocess.CompletedProcess(argv, 0, b'SystemState=stopping\n', b'')
        with mock.patch.object(monitor.subprocess, 'run', side_effect=run):
            self.assertEqual(monitor._pid1_read('show', '-p', 'SystemState'), STOPPING)
        argv, kwargs = calls[0]
        self.assertEqual(argv, ('/usr/bin/systemctl', 'show', '-p', 'SystemState'))
        self.assertEqual(kwargs['timeout'], 2.0)
        self.assertEqual(kwargs['stdin'], subprocess.DEVNULL)
        self.assertEqual(set(kwargs['env']), {'PATH', 'LANG', 'LC_ALL'})
        for result in (subprocess.CompletedProcess((), 1, b'', b'Failed to connect to bus'),
                       subprocess.CompletedProcess((), 0, b'x' * ((1 << 16) + 1), b'')):
            with mock.patch.object(monitor.subprocess, 'run', return_value=result), \
                    self.assertRaises(policy.ForeignPolicyRefused):
                monitor._pid1_read('show', '-p', 'SystemState')
        with mock.patch.object(monitor.subprocess, 'run', return_value=subprocess.CompletedProcess(
                (), 0, b'SystemState=\xff\n', b'')), self.assertRaises(UnicodeDecodeError):
            monitor._pid1_read('show', '-p', 'SystemState')


class Clock:
    def __init__(self):
        self.now = 1000.0
        self.sleeps = 0

    def monotonic(self):
        return self.now

    def sleep(self, seconds, limit):
        self.sleeps += 1
        if self.sleeps > limit:
            raise TimeoutError('still frozen')
        self.now += seconds


class Freeze(unittest.TestCase):
    def freeze(self, verdicts, *, grant=False, trip=None, limit=200, view=('items', True)):
        clock = self.clock = Clock()
        sequence = list(verdicts)
        self.grant_calls = 0
        self.verdict_calls = 0

        def next_verdict():
            self.verdict_calls += 1
            return sequence.pop(0) if len(sequence) > 1 else sequence[0]

        def live(found):
            self.grant_calls += 1
            return grant
        with mock.patch.object(monitor, 'shutdown_verdict', next_verdict), \
                mock.patch.object(monitor, '_window_view', return_value=view), \
                mock.patch.object(monitor, 'live_client_grant', side_effect=live), \
                mock.patch.object(monitor, 'tripwire', side_effect=trip or (lambda *a: None)), \
                mock.patch.object(monitor, '_freeze_fields', return_value={'uplink': 'uplink0'}), \
                mock.patch.object(monitor.time, 'monotonic', clock.monotonic), \
                mock.patch.object(monitor.time, 'sleep', lambda s: clock.sleep(s, limit)):
            return monitor.shutdown_freeze({'guard': None})

    def test_not_shutdown_records_at_once(self):
        self.assertEqual(self.freeze(['denied']), ('denied', False))
        self.assertEqual(self.clock.sleeps, 0)

    def test_first_unknown_waits_one_second_only(self):
        self.assertEqual(self.freeze(['unknown']), ('unknown', False))
        self.assertGreaterEqual(self.clock.now - 1000.0, monitor.FIRST_UNKNOWN_SECONDS)
        self.assertLess(self.clock.now - 1000.0, 2.0)
        self.assertEqual(self.freeze(['unknown', 'unknown', 'confirmed', 'denied']), ('denied', True))
        self.assertEqual(self.freeze(['unknown', 'unknown', 'unknown', 'confirmed']), ('unknown', False))

    def test_confirmed_never_returns(self):
        with self.assertRaises(TimeoutError):
            self.freeze(['confirmed'])
        # Once before any PID1 read, once again at freeze entry.
        self.assertEqual(self.grant_calls, 2)

    def test_grant_is_checked_before_any_pid1_read(self):
        for grant in (True, None):
            for verdicts in (['confirmed'], ['unknown'], ['denied']):
                with self.subTest(grant=grant, verdicts=verdicts):
                    self.assertEqual(self.freeze(verdicts, grant=grant), ('grant', False))
                    self.assertEqual((self.grant_calls, self.verdict_calls, self.clock.sleeps),
                                     (1, 0, 0))
        self.assertEqual(self.freeze(['denied']), ('denied', False))
        self.assertEqual((self.grant_calls, self.verdict_calls), (1, 1))

    def test_exec_race_inside_window_tolerated_then_five_seconds_unknown(self):
        with self.assertRaises(TimeoutError):
            self.freeze(['confirmed'] + ['unknown'] * 8 + ['confirmed'])
        self.assertEqual(self.freeze(['confirmed'] + ['unknown'] * 30), ('unknown', True))
        self.assertGreaterEqual(self.clock.now - 1000.0, monitor.FREEZE_UNKNOWN_SECONDS)

    def test_cancel_conflict_failure_after_freeze(self):
        self.assertEqual(self.freeze(['confirmed', 'confirmed', 'denied']), ('denied', True))

    def test_live_or_unprovable_grant_is_never_suppressed(self):
        for grant in (True, None):
            self.assertEqual(self.freeze(['confirmed'], grant=grant), ('grant', False))
        self.assertEqual(self.freeze(['confirmed'], view=(None, False), grant=None), ('grant', False))

    def test_tripwire_ends_the_window(self):
        self.assertEqual(self.freeze(['confirmed'], trip=lambda *a: 'guard'), ('tripwire', True))
        hits = iter([None, None, 'links'])
        self.assertEqual(self.freeze(['confirmed'], trip=lambda *a: next(hits)), ('tripwire', True))

    def test_frozen_window_writes_and_locks_nothing(self):
        forbid = mock.Mock(side_effect=AssertionError('write or lock while frozen'))
        with mock.patch('builtins.print', forbid), mock.patch('builtins.open', forbid), \
                mock.patch.object(monitor, 'publish_drift', forbid), \
                mock.patch.object(monitor, 'revoke', forbid), \
                mock.patch.object(monitor, 'guard_lock', forbid), \
                mock.patch.object(monitor.os, 'open', forbid), \
                mock.patch.object(monitor.fcntl, 'flock', forbid), \
                mock.patch.object(monitor.subprocess, 'run', forbid), \
                mock.patch.object(monitor.sys, 'stderr', mock.Mock(write=forbid)), \
                mock.patch.object(monitor.sys, 'stdout', mock.Mock(write=forbid)):
            with self.assertRaises(TimeoutError):
                self.freeze(['confirmed'], trip=lambda *a: None)
        forbid.assert_not_called()


class GrantFirst(unittest.TestCase):
    """A refusal with a live client grant revokes before any PID1 read.

    Real nft readbacks and the real main loop, window view, grant check and
    PID1 readers; only /usr/bin/systemctl is replaced by a stand-in that
    hangs like PID1 during a daemon-reload, under the product's own 2 s
    read timeout.
    """

    def refusal_to_revoke(self, variant_name, live):
        doc = NFT['nft-1.0.9']
        ruleset = doc['variants'][variant_name]['loaded'].encode()
        real_run = subprocess.run
        events = []
        with tempfile.TemporaryDirectory() as directory:
            standin = Path(directory) / 'systemctl'
            standin.write_text('#!/bin/sh\nexec sleep 30\n', encoding='ascii')
            standin.chmod(0o700)

            def run(argv, **kwargs):
                argv = tuple(argv)
                if argv[0] == '/usr/bin/systemctl':
                    events.append(('systemctl', time.monotonic()))
                    self.assertEqual(kwargs.get('timeout'), monitor.PID1_READ_SECONDS)
                    return real_run((str(standin),) + argv[1:], **kwargs)
                self.assertEqual(argv, monitor.RULESET_ARGV)
                events.append(('nft', time.monotonic()))
                return subprocess.CompletedProcess(argv, 0, ruleset, b'')

            def refused(*_args):
                events.append(('refusal', time.monotonic()))
                raise policy.ForeignPolicyRefused('foreign change')

            def exe():
                events.append(('pid1_exe', time.monotonic()))
                return False

            class Netlink:
                def bind(self, address):
                    pass
            with cgroupfs(live), \
                    mock.patch.object(monitor.subprocess, 'run', side_effect=run), \
                    mock.patch.object(monitor.socket, 'socket', return_value=Netlink(), create=True), \
                    mock.patch.object(monitor.socket, 'AF_NETLINK', 16, create=True), \
                    mock.patch.object(monitor.socket, 'SOCK_NONBLOCK', 2048, create=True), \
                    mock.patch.object(monitor.os, 'geteuid', return_value=0), \
                    mock.patch.object(monitor.select, 'select', return_value=([], [], [])), \
                    mock.patch.object(monitor, 'stable_assessment', side_effect=refused), \
                    mock.patch.object(monitor, '_pid1_exe_is_shutdown', side_effect=exe), \
                    mock.patch.object(monitor, 'state', return_value=(b'', {'armed': '1'})), \
                    mock.patch.object(monitor, 'publish_drift',
                                      side_effect=lambda lp: events.append(('publish', time.monotonic()))), \
                    mock.patch.object(monitor, 'revoke',
                                      side_effect=lambda **kw: events.append(('revoke', time.monotonic()))), \
                    mock.patch('builtins.print'):
                monitor.monitor()
        names = [name for name, _when in events]
        when = dict((name, at) for name, at in reversed(events))
        return names, when['revoke'] - when['refusal']

    def test_live_grant_revokes_without_reading_a_hung_pid1(self):
        doc = NFT['nft-1.0.9']
        live = doc['variants']['fwt-grant-mgr']['cgroup_ids']
        names, delay = self.refusal_to_revoke('fwt-grant-mgr', live)
        self.assertEqual(names, ['refusal', 'nft', 'revoke'])
        self.assertLess(delay, 0.5)

    def test_control_without_a_grant_the_stand_in_really_hangs(self):
        doc = NFT['nft-1.0.9']
        live = doc['variants']['fwt-deny-mgr']['cgroup_ids']
        names, delay = self.refusal_to_revoke('fwt-deny-mgr', live)
        self.assertEqual(names[:2], ['refusal', 'nft'])
        self.assertIn('systemctl', names)
        self.assertEqual(names[-1], 'revoke')
        self.assertGreaterEqual(delay, monitor.PID1_READ_SECONDS)


def guard_variant(doc, name, key='loaded'):
    return items(doc['variants'][name][key])


class GuardTripwire(unittest.TestCase):
    TRANSITIONS = (
        # (granted, deny) as the product writes them, same profile and ports
        ('fwt-grant-mgr', 'fwt-deny-mgr'), ('fwt-grant-mgr-scoped-local', 'fwt-deny-mgr'),
        ('fwt-grant', 'fwt-deny'), ('fwt-grant-mgr', 'fwt-deny-ports'),
        ('fwt-deny-mgr', 'fwt-deny-ports'),
        ('wrs-grant-mgr', 'wrs-deny-mgr'), ('wrs-grant-mgr-local', 'wrs-deny-mgr'),
        ('wrs-grant-mgr-scoped', 'wrs-deny-mgr'), ('wrs-grant-mgr', 'wrs-deny'),
        ('wrs-deny-mgr', 'wrs-deny'),
        ('ps-grant-mgr-scoped', 'ps-deny-mgr'), ('ps-grant-mgr-scoped', 'ps-deny'),
        ('ps-deny-mgr', 'ps-deny'),
    )

    def ids(self, doc, name):
        variant = doc['variants'][name]
        return {path: number for path, number in variant['cgroup_ids'].items()}

    def test_fixture_is_bound_to_the_committed_render_function(self):
        digest = hashlib.sha256(harness.render_function().encode()).hexdigest()
        for version, doc in NFT.items():
            self.assertEqual(doc['render_function_sha256'], digest, version)
        self.assertEqual(sorted(NFT), ['nft-1.0.6', 'nft-1.0.9'])

    def test_every_product_deny_transition_removes_only_accepts(self):
        for version, doc in NFT.items():
            for granted, deny in self.TRANSITIONS:
                with self.subTest(version=version, granted=granted, deny=deny):
                    live = self.ids(doc, deny)
                    with cgroupfs(live):
                        baseline = monitor._guard_view(guard_variant(doc, granted))
                        current = guard_variant(doc, deny)
                        self.assertIs(monitor.guard_loosened(current, baseline), False)
                        self.assertIs(monitor.live_client_grant(current), False)
                    # The manager stops: nft prints its pruned cgroup as an id.
                    if 'pruned_manager' in doc['variants'][deny]:
                        pruned = guard_variant(doc, deny, 'pruned_manager')
                        self.assertTrue(any(isinstance(right, str) and right.isdigit() for right in
                                            self.operands(pruned)))
                        with cgroupfs({}):
                            self.assertIs(monitor.guard_loosened(pruned, baseline), False)
                            self.assertIs(monitor.live_client_grant(pruned), False)

    def test_grant_reverse_and_reorder_are_loosening(self):
        for version, doc in NFT.items():
            for granted, deny in self.TRANSITIONS:
                with self.subTest(version=version, granted=granted, deny=deny):
                    live = self.ids(doc, granted)
                    with cgroupfs(live):
                        baseline = monitor._guard_view(guard_variant(doc, deny))
                        self.assertIs(monitor.guard_loosened(guard_variant(doc, granted), baseline), True)

    @staticmethod
    def operands(found):
        return [statement['match']['right'] for kind, obj in found if kind == 'rule'
                for statement in obj['expr'] if 'match' in statement and
                monitor._is_cgroupv2(statement['match'].get('left'))]

    def test_cgroup_path_string_id_and_integer_id_are_one_operand(self):
        doc = NFT['nft-1.0.9']
        live = self.ids(doc, 'fwt-deny-mgr')
        with cgroupfs(live):
            baseline = monitor._guard_view(guard_variant(doc, 'fwt-deny-mgr'))
        pruned = guard_variant(doc, 'fwt-deny-mgr', 'pruned_manager')
        as_int = json.loads(json.dumps(pruned))
        for kind, obj in as_int:
            for statement in obj.get('expr', []):
                match = statement.get('match')
                if match and monitor._is_cgroupv2(match.get('left')):
                    match['right'] = int(match['right'])
        with cgroupfs({}):
            self.assertIs(monitor.guard_loosened(pruned, baseline), False)
            self.assertIs(monitor.guard_loosened(as_int, baseline), False)
        # A live path naming a different cgroup than the assessed one adds an exemption.
        other = {path: number + 7 for path, number in live.items()}
        with cgroupfs(other):
            self.assertIs(monitor.guard_loosened(guard_variant(doc, 'fwt-deny-mgr'), baseline), True)

    def test_unusable_operands_are_no_evidence_and_never_raise(self):
        doc = NFT['nft-1.0.9']
        live = self.ids(doc, 'fwt-deny-mgr')
        with cgroupfs(live):
            baseline = monitor._guard_view(guard_variant(doc, 'fwt-deny-mgr'))
        for right in ('/system.slice/systemd-networkd.service', 'system.slice/../x',
                      'system.slice/../system.slice/systemd-networkd.service',
                      'system.slice/./systemd-networkd.service', {'set': []}, None, 0, -3, '', 'a\0b'):
            current = json.loads(json.dumps(guard_variant(doc, 'fwt-deny-mgr')))
            for kind, obj in current:
                for statement in obj.get('expr', []):
                    match = statement.get('match')
                    if match and monitor._is_cgroupv2(match.get('left')):
                        match['right'] = right
            with self.subTest(right=right), cgroupfs(live):
                self.assertIsNone(monitor.guard_loosened(current, baseline))
        # A cgroup pruned between nft's read and the stat: no evidence this poll.
        with cgroupfs({}):
            self.assertIsNone(monitor.guard_loosened(guard_variant(doc, 'fwt-deny-mgr'), baseline))

    def test_real_loosened_guard_readbacks(self):
        expected_with_baseline = {
            'guard-dormant': True, 'guard-counter': True, 'guard-set': True, 'guard-quota': True,
            'guard-extra-chain': True, 'guard-policy-accept': True, 'guard-insert-accept': True,
            'foreign-route-output': False, 'foreign-nat-output': False,
            'foreign-netdev-ingress': False, 'foreign-inet-ingress': False,
            'foreign-filter-output': False}
        baseline_free = dict(expected_with_baseline)
        baseline_free.update({'guard-insert-accept': None, 'foreign-route-output': None,
                              'foreign-nat-output': None, 'foreign-netdev-ingress': None,
                              'foreign-inet-ingress': None, 'foreign-filter-output': None})
        live = {'system.slice/systemd-networkd.service': 4242}
        for version, doc in NFT.items():
            with cgroupfs(live):
                baseline = monitor._guard_view(guard_variant(doc, 'fwt-deny-mgr'))
                self.assertIs(monitor.guard_loosened(guard_variant(doc, 'fwt-deny-mgr'), baseline), False)
                for name, want in expected_with_baseline.items():
                    with self.subTest(version=version, name=name):
                        loose = items(doc['loose'][name])
                        self.assertIs(monitor.guard_loosened(loose, baseline), want)
                        self.assertIs(monitor.guard_loosened(loose, None), baseline_free[name])

    def test_dormant_table_flags_appear_in_the_real_readback(self):
        for version, doc in NFT.items():
            tables = [obj for kind, obj in items(doc['loose']['guard-dormant']) if kind == 'table']
            self.assertEqual(len(tables), 1)
            self.assertIn('flags', tables[0], version)

    def test_baseline_free_shape(self):
        doc = NFT['nft-1.0.9']
        base = guard_variant(doc, 'fwt-deny-mgr')

        def edited(change):
            value = json.loads(json.dumps(base))
            change(value)
            return value

        def drop_table(value):
            value[:] = [(k, o) for k, o in value if monitor._owner(k, o) != ('inet', 'aegis_device_guard')]

        def prio(value):
            for kind, obj in value:
                if kind == 'chain' and obj['name'] == 'postroute':
                    obj['prio'] = 90

        def policy_accept(value):
            for kind, obj in value:
                if kind == 'chain' and obj['name'] == 'forward':
                    obj['policy'] = 'accept'

        def remove_terminal(chain):
            def change(value):
                rows = [i for i, (k, o) in enumerate(value) if k == 'rule' and o['chain'] == chain]
                del value[rows[-1]]
            return change

        def duplicate_table(value):
            value.append(['table', {'family': 'inet', 'name': 'aegis_device_guard', 'handle': 99}])

        def unknown_chain_rule(value):
            value.append(['rule', {'family': 'inet', 'table': 'aegis_device_guard', 'chain': 'r20',
                                   'handle': 98, 'expr': [{'accept': None}]}])

        for name, change in (('missing', drop_table), ('prio', prio), ('policy', policy_accept),
                             ('output-drop', remove_terminal('output')),
                             ('forward-drop', remove_terminal('forward')),
                             ('postroute-drop', remove_terminal('postroute')),
                             ('two tables', duplicate_table), ('orphan rule', unknown_chain_rule)):
            with self.subTest(name=name):
                current = [tuple(item) for item in edited(change)]
                self.assertIs(monitor.guard_loosened(current, None), True)
                with self.assertRaises(monitor._Loosened):
                    monitor._guard_rules(current)

    def test_rule_changes_against_the_baseline(self):
        doc = NFT['nft-1.0.9']
        live = self.ids(doc, 'fwt-deny-mgr')
        base = guard_variant(doc, 'fwt-deny-mgr')
        with cgroupfs(live):
            baseline = monitor._guard_view(base)

        def output_rows(value):
            return [i for i, (k, o) in enumerate(value) if k == 'rule' and o['chain'] == 'output']

        mark_clear = json.loads(json.dumps(base))
        del mark_clear[output_rows(mark_clear)[0]]
        reordered = json.loads(json.dumps(base))
        rows = output_rows(reordered)
        reordered[rows[1]], reordered[rows[2]] = reordered[rows[2]], reordered[rows[1]]
        comment = json.loads(json.dumps(base))
        comment[output_rows(comment)[1]][1]['comment'] = 'r20-foreign'
        accept_removed = json.loads(json.dumps(base))
        del accept_removed[output_rows(accept_removed)[1]]
        with cgroupfs(live):
            self.assertIs(monitor.guard_loosened([tuple(i) for i in mark_clear], baseline), True)
            self.assertIs(monitor.guard_loosened([tuple(i) for i in reordered], baseline), True)
            self.assertIs(monitor.guard_loosened([tuple(i) for i in comment], baseline), True)
            self.assertIs(monitor.guard_loosened([tuple(i) for i in accept_removed], baseline), False)

    def test_only_accepts_removed(self):
        a, b, c, d = ('a', True), ('b', False), ('c', True), ('d', False)
        self.assertTrue(monitor._only_accepts_removed([a, b, c, d], [a, b, c, d]))
        self.assertTrue(monitor._only_accepts_removed([b, d], [a, b, c, d]))
        self.assertFalse(monitor._only_accepts_removed([a, c, d], [a, b, c, d]))
        self.assertFalse(monitor._only_accepts_removed([a, b, c], [a, b, c, d]))
        self.assertFalse(monitor._only_accepts_removed([c, a, b, d], [a, b, c, d]))
        self.assertFalse(monitor._only_accepts_removed([a, ('x', True), b, c, d], [a, b, c, d]))
        self.assertTrue(monitor._only_accepts_removed([], [a, c]))
        self.assertFalse(monitor._only_accepts_removed([], [a, b]))
        # an added row after every assessed row, even an accept, is loosening
        self.assertFalse(monitor._only_accepts_removed([a, c, ('x', True)], [a, c]))
        self.assertFalse(monitor._only_accepts_removed([('x', True)], []))
        self.assertFalse(monitor._only_accepts_removed([c, ('x', True)], [a, c]))


class RerouteTripwire(unittest.TestCase):
    def owned(self, doc, name):
        found = []
        for kind, obj in items(doc['loose'][name]):
            obj = dict(obj)
            if obj.get('name' if kind == 'table' else 'table') == 'r20q_nat':
                obj['name' if kind == 'table' else 'table'] = 'aegis_auto_local_redirect'
            found.append((kind, obj))
        return found

    def test_real_foreign_chain_readbacks(self):
        for version, doc in NFT.items():
            baseline = monitor._reroute_view(guard_variant(doc, 'fwt-deny-mgr'))
            self.assertEqual(baseline, {})
            for name, want in (('foreign-route-output', True), ('foreign-nat-output', True),
                               ('foreign-netdev-ingress', True), ('foreign-inet-ingress', True),
                               ('foreign-filter-output', False), ('guard-insert-accept', False)):
                with self.subTest(version=version, name=name), cgroupfs({}):
                    found = items(doc['loose'][name])
                    self.assertIs(monitor.reroute_loosened(found, baseline), want)
                    self.assertIs(monitor.reroute_loosened(found, None), want)

    def test_owned_redirect_chain_lifecycle(self):
        doc = NFT['nft-1.0.9']
        with cgroupfs({}):
            present = self.owned(doc, 'foreign-nat-output')
            baseline = monitor._reroute_view(present)
            self.assertEqual(len(baseline), 1)
            self.assertIs(monitor.reroute_loosened(present, baseline), False)
            self.assertIs(monitor.reroute_loosened(present, None), False)  # owned name, no baseline
            gone = guard_variant(doc, 'fwt-deny-mgr')
            self.assertIs(monitor.reroute_loosened(gone, baseline), False)  # client stop deletes it
            added = present + [('rule', {'family': 'ip', 'table': 'aegis_auto_local_redirect',
                                         'chain': 'out', 'handle': 77,
                                         'expr': [{'mangle': {'key': {'meta': {'key': 'mark'}},
                                                              'value': 0xa361c001}}]})]
            self.assertIs(monitor.reroute_loosened(added, baseline), True)
            recreated = [(k, dict(o, handle=o.get('handle', 0) + 50) if k == 'chain' else o)
                         for k, o in present]
            self.assertIs(monitor.reroute_loosened(recreated, baseline), True)
            self.assertIs(monitor.reroute_loosened(items(doc['loose']['foreign-route-output']),
                                                   baseline), True)


class LinkTripwire(unittest.TestCase):
    PINNED = frozenset((
        'bad uplink', 'link inventory bound', 'netkit device', 'XDP attachment',
        'tc ingress/clsact qdisc', 'tc filter', 'protected interface missing', 'forwarding host',
        'BPF interface query bound', 'invalid root BPF query result',
        'unsupported bpf syscall architecture', 'BPF attribute bound',
        'XDP/netfilter/TCX/netkit BPF link', 'BPF link inventory bound',
        'BPF program attached to protected interface', 'BPF attachment query unavailable',
        'capture interface type', 'capture interface owner'))

    @staticmethod
    def need_messages(names):
        tree = ast.parse((LIB / 'aegis_auto_foreign_policy.py').read_text())
        found = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef) and node.name in names:
                for call in ast.walk(node):
                    if isinstance(call, ast.Call) and getattr(call.func, 'id', None) == 'need':
                        message = call.args[1]
                        assert isinstance(message, ast.Constant), ast.dump(message)
                        found.add(message.value)
        return found

    def test_closed_reason_codes_are_pinned(self):
        self.assertEqual(self.need_messages({'check_links', 'bpf_bindings', '_local_bpf_bindings'}),
                         self.PINNED)
        self.assertTrue(monitor.LINK_BYPASS_REASONS < self.PINNED)

    def test_only_bypass_reasons_fire(self):
        bypass = {'netkit device', 'XDP attachment', 'tc ingress/clsact qdisc', 'tc filter',
                  'forwarding host', 'XDP/netfilter/TCX/netkit BPF link',
                  'BPF program attached to protected interface',
                  'capture interface type', 'capture interface owner'}
        self.assertEqual(set(monitor.LINK_BYPASS_REASONS), bypass)
        for reason in sorted(self.PINNED):
            with self.subTest(reason=reason), mock.patch.object(
                    monitor, 'check_links', side_effect=policy.ForeignPolicyRefused(reason)):
                self.assertIs(monitor.links_loosened('uplink0'), True if reason in bypass else None)
        for raised in (policy.PolicyInputUnavailable(('tc', '-j', 'qdisc', 'show', 'dev', 'x'), 1,
                                                      b'Cannot find device'),
                       policy.ForeignPolicyRefused('JSON size bound'),
                       policy.ForeignPolicyRefused('policy command output exceeds bound'),
                       policy.ForeignPolicyRefused('tc filter', 'extra'),
                       OSError(errno.EPERM, 'bpf'), KeyError('ifname'), subprocess.TimeoutExpired('tc', 3)):
            with self.subTest(raised=raised), mock.patch.object(monitor, 'check_links', side_effect=raised):
                self.assertIsNone(monitor.links_loosened('uplink0'))
        with mock.patch.object(monitor, 'check_links', return_value=['lo', 'uplink0']):
            self.assertIs(monitor.links_loosened('uplink0'), False)
        self.assertIsNone(monitor.links_loosened(None))

    def test_protected_link_names_against_the_baseline(self):
        fields = {'uplink': 'uplink0', 'capture_interface': 'aegis-tun0'}
        assessed = frozenset({(1, 'lo'), (2, 'uplink0'), (5, 'aegis-tun0'), (6, 'docker0')})
        for current, want in (
                (assessed, False),
                (frozenset({(1, 'lo'), (2, 'uplink0'), (6, 'docker0')}), False),  # TUN removed
                (frozenset({(1, 'lo'), (2, 'uplink0'), (9, 'aegis-tun0')}), True),  # recreated
                (frozenset({(1, 'lo'), (6, 'uplink0'), (5, 'aegis-tun0')}), True),  # renamed onto
                (frozenset({(1, 'lo'), (2, 'uplink0'), (7, 'veth9')}), False)):
            with self.subTest(current=sorted(current)), \
                    mock.patch.object(monitor, 'link_identities', return_value=current):
                self.assertIs(monitor.link_names_loosened(fields, assessed), want)
        with mock.patch.object(monitor, 'link_identities', side_effect=ValueError('inventory')):
            self.assertIsNone(monitor.link_names_loosened(fields, assessed))

    def test_capture_name_without_baseline_must_be_a_tun(self):
        fields = {'uplink': 'uplink0', 'capture_interface': 'aegis-tun0'}
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            link = root / 'aegis-tun0'
            link.mkdir()
            (link / 'ifindex').write_text('9\n')
            current = frozenset({(1, 'lo'), (9, 'aegis-tun0')})
            with mock.patch.object(monitor, 'SYS_CLASS_NET', root), \
                    mock.patch.object(monitor, 'link_identities', return_value=current):
                self.assertIs(monitor.link_names_loosened(fields, None), True)  # macvlan/dummy
                (link / 'tun_flags').write_text('0x1001\n')
                self.assertIs(monitor.link_names_loosened(fields, None), False)  # TUN
                (link / 'tun_flags').write_text('0x1002\n')
                self.assertIs(monitor.link_names_loosened(fields, None), True)  # TAP
                (link / 'tun_flags').write_text('0x1003\n')
                self.assertIs(monitor.link_names_loosened(fields, None), True)  # not exactly TUN
                (link / 'tun_flags').unlink()
                (link / 'ifindex').write_text('10\n')
                self.assertIs(monitor.link_names_loosened(fields, None), False)  # vanished/raced


class LiveGrant(unittest.TestCase):
    def test_real_readbacks(self):
        for version, doc in NFT.items():
            variant = doc['variants']['fwt-grant-mgr']
            live = variant['cgroup_ids']
            client = doc['client_path']
            with self.subTest(version=version):
                with cgroupfs(live):
                    self.assertIs(monitor.live_client_grant(items(variant['loaded'])), True)
                    self.assertIs(monitor.live_client_grant(items(variant['pruned_client'])), False)
                    self.assertIs(monitor.live_client_grant(guard_variant(doc, 'fwt-deny-mgr')), False)
                with cgroupfs({k: v for k, v in live.items() if k != client}):
                    # nft read the path, then the cgroup was removed before the check
                    self.assertIs(monitor.live_client_grant(items(variant['loaded'])), False)
                with cgroupfs(live):
                    for name in ('wrs-grant-mgr-local', 'wrs-grant-mgr-scoped', 'ps-grant-mgr-scoped'):
                        self.assertIs(monitor.live_client_grant(
                            items(doc['variants'][name]['loaded'])), True, name)
        self.assertIsNone(monitor.live_client_grant(None))

    def test_unprovable_operands_are_not_proof_of_no_grant(self):
        rule = {'family': 'inet', 'table': 'aegis_device_guard', 'chain': 'output', 'handle': 9,
                'expr': [{'match': {'op': '==', 'left': {'socket': {'key': 'cgroupv2', 'level': 2}},
                                    'right': None}}, {'accept': None}]}
        for right in ('/system.slice/x.service', 'system.slice/../x', None, {'a': 1}, 0):
            rule['expr'][0]['match']['right'] = right
            with self.subTest(right=right):
                self.assertIsNone(monitor.live_client_grant([('rule', rule)]))
        self.assertIsNone(monitor.live_client_grant([('rule', dict(rule, expr='x'))]))


class WindowView(unittest.TestCase):
    def run_with(self, answers):
        calls = []

        def run(argv, **kwargs):
            calls.append(argv)
            code, out = answers[argv]
            return subprocess.CompletedProcess(argv, code, out, b'')
        with mock.patch.object(monitor.subprocess, 'run', side_effect=run):
            return monitor._window_view(), calls

    def test_fallbacks(self):
        doc = NFT['nft-1.0.9']
        ruleset = doc['variants']['fwt-deny-mgr']['loaded'].encode()
        (found, complete), calls = self.run_with({monitor.RULESET_ARGV: (0, ruleset)})
        self.assertTrue(complete)
        self.assertEqual(calls, [monitor.RULESET_ARGV])
        huge = b'{"nftables":[' + b'{"metainfo":{}},' * 300000 + b'{"metainfo":{}}]}'
        (found, complete), calls = self.run_with({monitor.RULESET_ARGV: (0, huge),
                                                 monitor.GUARD_ARGV: (0, ruleset)})
        self.assertEqual((complete, calls), (False, [monitor.RULESET_ARGV, monitor.GUARD_ARGV]))
        self.assertTrue(found)
        tables = json.dumps({'nftables': [{'table': {'family': 'ip', 'name': 'filter', 'handle': 1}}]}).encode()
        (found, complete), _ = self.run_with({monitor.RULESET_ARGV: (1, b''), monitor.GUARD_ARGV: (1, b''),
                                              monitor.TABLES_ARGV: (0, tables)})
        self.assertEqual(complete, False)
        self.assertIs(monitor.guard_loosened(found, None), True)  # proven absent
        present = json.dumps({'nftables': [{'table': {'family': 'inet', 'name': 'aegis_device_guard',
                                                      'handle': 1}}]}).encode()
        (found, complete), _ = self.run_with({monitor.RULESET_ARGV: (1, b''), monitor.GUARD_ARGV: (1, b''),
                                              monitor.TABLES_ARGV: (0, present)})
        self.assertEqual((found, complete), (None, False))
        (found, complete), _ = self.run_with({monitor.RULESET_ARGV: (1, b''), monitor.GUARD_ARGV: (1, b''),
                                              monitor.TABLES_ARGV: (1, b'')})
        self.assertEqual((found, complete), (None, False))

    def test_tripwire_names_the_first_positive_check(self):
        baseline = {'guard': None, 'reroute': None, 'links': None}
        fields = {'uplink': 'uplink0'}
        with mock.patch.object(monitor, 'guard_loosened', return_value=None), \
                mock.patch.object(monitor, 'reroute_loosened', return_value=True) as reroute, \
                mock.patch.object(monitor, 'links_loosened', return_value=None), \
                mock.patch.object(monitor, 'link_names_loosened', return_value=None):
            self.assertEqual(monitor.tripwire([], True, baseline, fields), 'reroute')
            self.assertIsNone(monitor.tripwire([], False, baseline, fields))  # partial view
            reroute.assert_called_once()
            self.assertIsNone(monitor.tripwire(None, True, baseline, fields))
        with mock.patch.object(monitor, 'guard_loosened', side_effect=KeyError('x')), \
                mock.patch.object(monitor, 'reroute_loosened', side_effect=TypeError()), \
                mock.patch.object(monitor, 'links_loosened', return_value=False), \
                mock.patch.object(monitor, 'link_names_loosened', return_value=True):
            self.assertEqual(monitor.tripwire([], True, baseline, fields), 'link_names')


class Baseline(unittest.TestCase):
    def setUp(self):
        self.doc = NFT['nft-1.0.9']
        self.raw = self.doc['variants']['fwt-deny-mgr']['loaded'].encode()
        self.live = self.doc['variants']['fwt-deny-mgr']['cgroup_ids']

    def test_refresh_keeps_the_last_good_baseline(self):
        baseline = {'raw': None, 'guard': None, 'reroute': None, 'links': None}
        links = frozenset({(1, 'lo')})
        with cgroupfs(self.live):
            monitor._refresh_baseline(baseline, [b'{}', self.raw], links)
        good = dict(baseline)
        self.assertEqual(good['raw'], self.raw)
        self.assertEqual(sorted(good['guard']), sorted(monitor.GUARD_CHAINS))
        for broken in ([b'{"nftables": 1}'], [b'not json'], [self.raw.replace(b'"drop"}}', b'"accept"}}', 1)]):
            with cgroupfs(self.live):
                monitor._refresh_baseline(baseline, broken, links)
            self.assertEqual(baseline, good)
        with cgroupfs({}):  # a cgroup pruned before its path could be resolved
            monitor._refresh_baseline(baseline, [self.raw.replace(b'"handle": 1,', b'"handle": 2,', 1)],
                                      links)
        self.assertEqual(baseline, good)
        monitor._refresh_baseline(baseline, [], links)
        monitor._refresh_baseline(None, [self.raw], links)
        self.assertEqual(baseline, good)
        with mock.patch.object(monitor, '_items', wraps=monitor._items) as parsed:
            monitor._refresh_baseline(baseline, [self.raw], links)
            self.assertEqual(parsed.call_count, 0)  # unchanged bytes: no work at all
            monitor._refresh_baseline(baseline, [self.raw], frozenset({(2, 'lo')}))
            self.assertEqual(parsed.call_count, 1)  # changed links: one re-parse

    def test_stable_assessment_uses_the_assessments_own_snapshot_after_the_locks(self):
        events = []

        @contextlib.contextmanager
        def guard_lock(**kwargs):
            events.append('lock')
            yield 9
            events.append('unlock')

        def assess(*args, **kwargs):
            # The real assessment reads the ruleset through the module's run().
            policy.run(*policy.RULESET)
            policy.run(*policy.RULESET)
            return {'foreign_projection_sha256': 'p'}

        def fake_run(*argv):
            events.append('read')
            return self.raw
        refresh = monitor._refresh_baseline

        def tracked(*args):
            events.append('refresh')
            return refresh(*args)
        baseline = {'raw': None, 'guard': None, 'reroute': None, 'links': None}
        links = frozenset({(1, 'lo'), (2, 'uplink0')})
        original = policy.run
        with mock.patch.object(monitor, 'guard_lock', guard_lock), \
                mock.patch.object(monitor, 'state', return_value=(b'', {'armed': '1', 'uplink': 'uplink0'})), \
                mock.patch.object(monitor, 'assessment_options', return_value={}), \
                mock.patch.object(monitor, 'assess_foreign_policy', side_effect=assess), \
                mock.patch.object(monitor, 'cgroup_members'), \
                mock.patch.object(monitor, 'get_generation', return_value=7), \
                mock.patch.object(monitor, 'link_identities', return_value=links), \
                mock.patch.object(policy, 'run', side_effect=fake_run), \
                mock.patch.object(monitor, '_refresh_baseline', side_effect=tracked), \
                mock.patch.object(monitor.subprocess, 'run', side_effect=AssertionError('extra read')), \
                cgroupfs(self.live):
            self.assertEqual(monitor.stable_assessment(object(), baseline), {'foreign_projection_sha256': 'p'})
        self.assertEqual(events, ['lock', 'read', 'read', 'unlock', 'refresh'])
        self.assertEqual(baseline['raw'], self.raw)
        self.assertEqual(baseline['links'], links)
        self.assertIs(policy.run, original)

    def test_capture_restores_run_and_ignores_other_reads(self):
        original = policy.run
        with self.assertRaises(KeyError):
            with monitor._ruleset_capture() as captured:
                self.assertIsNot(policy.run, original)
                raise KeyError('assessment refused')
        self.assertIs(policy.run, original)
        with mock.patch.object(policy, 'run', side_effect=lambda *argv: repr(argv).encode()):
            with monitor._ruleset_capture() as captured:
                policy.run('nft', '--json', 'list', 'table', 'inet', 'aegis_device_guard')
                policy.run(*policy.RULESET)
            self.assertEqual(captured, [repr(policy.RULESET).encode()])

    def test_mocked_or_refused_assessment_leaves_the_baseline(self):
        baseline = {'raw': b'x', 'guard': {'output': []}, 'reroute': {}, 'links': frozenset()}
        before = dict(baseline)
        with mock.patch.object(monitor, 'guard_lock', side_effect=lambda **_: contextlib.nullcontext(9)), \
                mock.patch.object(monitor, 'state', return_value=(b'', {'armed': '1', 'uplink': 'lo'})), \
                mock.patch.object(monitor, 'assessment_options', return_value={}), \
                mock.patch.object(monitor, 'assess_foreign_policy', return_value={'foreign_projection_sha256': 'p'}), \
                mock.patch.object(monitor, 'cgroup_members'), \
                mock.patch.object(monitor, 'get_generation', return_value=7), \
                mock.patch.object(monitor, 'link_identities', return_value=frozenset({(1, 'lo')})):
            monitor.stable_assessment(object(), baseline)
        self.assertEqual(baseline, before)


class MainLoop(unittest.TestCase):
    def loop(self, error, freeze, *, armed='1', print_error=None, revoke_error=None):
        calls = []

        class Netlink:
            def bind(self, address):
                pass

            def recvmsg(self, size):
                return b'x', None, 0, None

        def frozen(baseline):
            calls.append(('freeze', sorted(baseline)))
            if isinstance(freeze, BaseException):
                raise freeze
            return freeze

        def revoke(**kwargs):
            calls.append('revoke')
            if revoke_error is not None:
                raise revoke_error

        def printed(*args, **kwargs):
            if print_error is not None:
                raise print_error
        with mock.patch.object(monitor.socket, 'socket', return_value=Netlink(), create=True), \
                mock.patch.object(monitor.socket, 'AF_NETLINK', 16, create=True), \
                mock.patch.object(monitor.socket, 'SOCK_NONBLOCK', 2048, create=True), \
                mock.patch.object(monitor.os, 'geteuid', return_value=0), \
                mock.patch.object(monitor.select, 'select', return_value=([], [], [])), \
                mock.patch.object(monitor, 'stable_assessment', side_effect=error), \
                mock.patch.object(monitor, 'shutdown_freeze', side_effect=frozen), \
                mock.patch.object(monitor, 'state', return_value=(b'', {'armed': armed})), \
                mock.patch.object(monitor, 'publish_drift', side_effect=lambda lp: calls.append('publish')), \
                mock.patch.object(monitor, 'revoke', side_effect=revoke), \
                mock.patch('builtins.print', side_effect=printed):
            monitor.monitor()
        return calls

    def test_every_exception_class_is_classified_then_revoked(self):
        for error in (KeyError('x'), TypeError(), AttributeError(), IndexError(), LookupError(),
                      UnicodeDecodeError('ascii', b'', 0, 1, 'x'), AssertionError(), BrokenPipeError(),
                      ZeroDivisionError(), RecursionError(), policy.ForeignPolicyRefused('x'),
                      RuntimeError(), OSError(), ValueError(), subprocess.SubprocessError(),
                      monitor.CgroupTransition('x'), policy.PolicySnapshotChanged({}, {})):
            with self.subTest(error=type(error).__name__):
                self.assertEqual(self.loop(error, ('denied', False)),
                                 [('freeze', ['guard', 'links', 'raw', 'reroute']), 'revoke'])

    def test_suppressed_refusal_publishes_before_the_lock(self):
        for reason in ('denied', 'tripwire', 'unknown'):
            self.assertEqual(self.loop(KeyError('x'), (reason, True))[1:], ['publish', 'revoke'])
        self.assertEqual(self.loop(KeyError('x'), ('denied', True), armed='0')[1:], ['revoke'])
        for reason in ('grant', 'unknown', 'denied'):
            self.assertEqual(self.loop(KeyError('x'), (reason, False))[1:], ['revoke'])

    def test_classification_failure_still_revokes(self):
        self.assertEqual(self.loop(KeyError('x'), TypeError('bug'))[1:], ['revoke'])

    def test_confirmed_shutdown_never_revokes(self):
        class Forever(BaseException):
            pass
        with self.assertRaises(Forever):
            self.loop(policy.ForeignPolicyRefused('x'), Forever())

    def test_epipe_on_refusal_diagnostics_cannot_skip_revoke_or_record(self):
        self.assertEqual(self.loop(KeyError('x'), ('denied', True), print_error=BrokenPipeError())[1:],
                         ['publish', 'revoke'])
        self.assertEqual(self.loop(BrokenPipeError(), ('denied', False), print_error=BrokenPipeError())[1:],
                         ['revoke'])

    def test_record_survives_an_unknown_guard_lock_holder(self):
        """A frozen window that ends denied records before revoke() meets the lock."""
        calls = []
        with mock.patch.object(monitor.socket, 'socket', return_value=mock.Mock(), create=True), \
                mock.patch.object(monitor.socket, 'AF_NETLINK', 16, create=True), \
                mock.patch.object(monitor.socket, 'SOCK_NONBLOCK', 2048, create=True), \
                mock.patch.object(monitor.os, 'geteuid', return_value=0), \
                mock.patch.object(monitor.select, 'select', return_value=([], [], [])), \
                mock.patch.object(monitor, 'stable_assessment', side_effect=KeyError('x')), \
                mock.patch.object(monitor, 'shutdown_freeze', return_value=('denied', True)), \
                mock.patch.object(monitor, 'state', return_value=(b'', {'armed': '1'})), \
                mock.patch.object(monitor, 'publish_drift', side_effect=lambda lp: calls.append(('publish', lp))), \
                mock.patch.object(monitor, 'guard_lock', side_effect=BlockingIOError(errno.EAGAIN, 'held')), \
                mock.patch.object(monitor, 'stop_owned_units', side_effect=lambda units: calls.append('stop') or True), \
                mock.patch('builtins.print'):
            with self.assertRaises(BlockingIOError):
                monitor.monitor()
        self.assertEqual(calls, [('publish', True), 'stop'])


class StopPost(unittest.TestCase):
    def test_any_exception_class_revokes_once(self):
        class Custom(BaseException):
            pass
        for side in (KeyError('x'), TypeError(), SystemExit(1), KeyboardInterrupt(), GeneratorExit(),
                     Custom(), BrokenPipeError()):
            calls = []
            with self.subTest(side=type(side).__name__), \
                    mock.patch.object(monitor, 'rotation_stop_authorized', side_effect=side), \
                    mock.patch.object(monitor, 'revoke', side_effect=lambda **k: calls.append(k)):
                monitor.monitor_stop()
            self.assertEqual(calls, [{'leak_possible': True}])

    def test_only_a_true_rotation_proof_is_exempt(self):
        for value, want in ((True, 0), (1, 1), ('yes', 1), (False, 1), (None, 1), (object(), 1)):
            calls = []
            with mock.patch.object(monitor, 'rotation_stop_authorized', return_value=value), \
                    mock.patch.object(monitor, 'revoke', side_effect=lambda **k: calls.append(k)):
                monitor.monitor_stop()
            self.assertEqual(len(calls), want, value)


class RetiredHandoff(unittest.TestCase):
    def run_main(self, *argv):
        path = LIB / 'aegis_auto_foreign_monitor.py'
        code = compile(path.read_text(), str(path), 'exec')
        forbid = mock.Mock(side_effect=AssertionError('the retired flag must do nothing'))
        namespace = {'__name__': '__main__', '__file__': str(path)}
        with mock.patch.object(sys, 'argv', [str(path), *argv]), \
                mock.patch.object(os, 'open', forbid), mock.patch('builtins.open', forbid), \
                mock.patch.object(subprocess, 'run', forbid), mock.patch.object(subprocess, 'Popen', forbid), \
                mock.patch('fcntl.flock', forbid), mock.patch('socket.socket', forbid), \
                mock.patch('time.sleep', forbid):
            exec(code, namespace)
        forbid.assert_not_called()
        return namespace

    def test_shutdown_handoff_flag_is_inert(self):
        namespace = self.run_main('--shutdown-handoff')
        self.assertTrue(callable(namespace['monitor_stop']))

    def test_r19_surface_is_gone(self):
        for name in ('shutdown_handoff', 'clean_shutdown_stop_authorized', 'retire_old_shutdown_marker',
                     '_pid1_shutdown_job', 'SHUTDOWN_MARKER', 'SHUTDOWN_UNIT', 'FOREIGN_UNIT',
                     '_shutdown_deny_snapshot', '_shutdown_marker_write'):
            self.assertFalse(hasattr(monitor, name), name)
        source = (LIB / 'aegis_auto_foreign_monitor.py').read_text()
        self.assertNotIn('auto-clean-shutdown-once', source)
        self.assertNotIn('45.0', source)

    def test_installed_r19_unit_stays_byte_identical_and_names_the_inert_flag(self):
        unit = (REPO / 'packaging/systemd/aegis-auto-clean-shutdown.service').read_bytes()
        self.assertEqual(hashlib.sha256(unit).hexdigest(),
                         '728f4efa7691196832b9a013e240c97087e08bc8646c2eb57ea47bfde658fc4c')
        self.assertIn(b'aegis_auto_foreign_monitor.py --shutdown-handoff\n', unit)

    def test_leftover_r19_marker_is_read_by_no_bind_path_and_removed_by_recovery_and_purge(self):
        guard = (SCRIPTS / 'aegis-device-egress-guard.sh').read_text()
        lines = [line for line in guard.splitlines() if 'auto-clean-shutdown-once.json' in line]
        self.assertEqual(len(lines), 1)
        self.assertIn('aegis_root_remove', lines[0])
        start = guard.index('remove_guard_ownership() {')
        self.assertIn('auto-clean-shutdown-once.json', guard[start:guard.index('\n}\n', start)])
        purge = (SCRIPTS / 'purge-installed-aegis.sh').read_text()
        self.assertIn('remove_path "$(path_in_root "/var/lib/aegis-install/client")"', purge)
        for path in LIB.glob('*.py'):
            self.assertNotIn('auto-clean-shutdown-once', path.read_text(), path.name)


class ProductForm(unittest.TestCase):
    SOURCE = (LIB / 'aegis_auto_foreign_monitor.py').read_text()

    def test_no_container_patch_or_switch_reaches_the_product(self):
        for text in ('/opt/', 'r20b', 'r20i', 'r20q', 'TRIPWIRE', 'tripwire-off', 'b-monitor.jsonl',
                     '_r20b_fixture_admits', 'redirect-fixture', '_pid1_read_product', 'getenv'):
            self.assertNotIn(text, self.SOURCE, text)
        tree = ast.parse(self.SOURCE)
        bplus = {'shutdown_verdict', 'shutdown_freeze', 'tripwire', 'guard_loosened', 'reroute_loosened',
                 'links_loosened', 'link_names_loosened', 'live_client_grant', '_window_view',
                 '_refresh_baseline', '_ruleset_capture', '_pid1_read', '_nft_items', 'monitor_stop'}
        functions = {node.name: node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)}
        self.assertLessEqual(bplus, set(functions))
        for name in bplus:
            text = ast.get_source_segment(self.SOURCE, functions[name])
            self.assertNotIn('environ', text, name)
            self.assertNotIn('exists(', text, name)
        for text in ('_r20b_fixture_admits', 'redirect-fixture', '/opt/'):
            self.assertNotIn(text, (LIB / 'aegis_auto_foreign_policy.py').read_text())
        watchdog = (LIB / 'aegis_auto_guardian_watchdog.py').read_text()
        self.assertIn('INSTALL = Path("/var/lib/aegis-install/client/auto-guardian-install.json")', watchdog)
        self.assertIn('UNIT_PATH = Path("/etc/systemd/system/aegis-auto-guardian-watchdog.service")', watchdog)

    def test_trace_seam_is_a_no_op(self):
        node = next(n for n in ast.walk(ast.parse(self.SOURCE))
                    if isinstance(n, ast.FunctionDef) and n.name == '_trace')
        self.assertEqual(len(node.body), 2)
        self.assertIsInstance(node.body[0], ast.Expr)  # docstring
        self.assertIsInstance(node.body[1], ast.Return)
        self.assertIsNone(node.body[1].value.value)
        forbid = mock.Mock(side_effect=AssertionError('trace wrote'))
        with mock.patch('builtins.open', forbid), mock.patch('builtins.print', forbid):
            self.assertIsNone(monitor._trace('freeze_enter', error=KeyError('x')))

    def test_sigterm_keeps_its_default_disposition(self):
        """systemd-shutdown's SIGTERM ends a frozen monitor; no handler can write."""
        uses = [node for node in ast.walk(ast.parse(self.SOURCE)) if isinstance(node, ast.Attribute) and
                isinstance(node.value, ast.Name) and node.value.id == 'signal']
        self.assertEqual(uses, [])
        self.assertNotIn('atexit', self.SOURCE)
        self.assertNotIn('sigaction', self.SOURCE)
        result = subprocess.run([sys.executable, '-I', '-B', '-c',
                                 'import signal,sys; sys.path.insert(0, sys.argv[1]); '
                                 'import aegis_auto_foreign_monitor; '
                                 'print(signal.getsignal(signal.SIGTERM) is signal.SIG_DFL)', str(LIB)],
                                capture_output=True, text=True, timeout=60)
        self.assertEqual((result.returncode, result.stdout.strip()), (0, 'True'), result.stderr)

    def test_main_reports_only_a_fixed_line(self):
        self.assertIn("    except Exception:\n        # A failing monitor is an alarm", self.SOURCE)


class UnitFacts(unittest.TestCase):
    """B relies on the monitor and the guard having no stop job in a shutdown."""

    def test_monitor_unit_has_no_shutdown_stop_job(self):
        text = (REPO / 'packaging/systemd/aegis-foreign-policy-monitor.service').read_text()
        lines = [line.strip() for line in text.splitlines()]
        self.assertIn('DefaultDependencies=no', lines)
        self.assertIn('BindsTo=aegis-device-egress-guard.service', lines)
        self.assertIn('PartOf=aegis-device-egress-guard.service', lines)
        self.assertFalse([line for line in lines if line.startswith('Conflicts=')])
        before = [line for line in lines if line.startswith('Before=')]
        self.assertEqual(before, ['Before=network-pre.target'])
        self.assertFalse([line for line in lines if line.startswith(('BindsTo=', 'PartOf=', 'Requisite='))
                          and 'aegis-device-egress-guard.service' not in line])
        self.assertIn('ExecStopPost=/usr/bin/python3 -I -B /usr/local/lib/aegis/helpers/lib/'
                      'aegis_auto_foreign_monitor.py --stopped', lines)

    def test_guard_unit_has_no_stop_job_or_exec_stop(self):
        install = (REPO / 'install.sh').read_text()
        start = install.index('install_atomic_write "${SYSTEMD_DIR}/aegis-device-egress-guard.service"')
        unit = install[start:install.index('\nEOF\n', start)]
        lines = [line.strip() for line in unit.splitlines()]
        self.assertIn('DefaultDependencies=no', lines)
        self.assertFalse([line for line in lines if line.startswith(('ExecStop=', 'ExecStopPost=',
                                                                     'Conflicts='))])


class SelectedRelayExclusion(unittest.TestCase):
    def test_auto_refuses_selected_relay_and_assessment_refuses_its_table(self):
        install = (REPO / 'install.sh').read_text()
        self.assertIn("echo 'Automatic device V2 does not admit the separate relay Geneva selection.' >&2",
                      install)
        table = {'nftables': [{'table': {'family': 'netdev', 'name': 'aegis_relay_geneva_device_guard',
                                         'handle': 3}}]}
        with self.assertRaises(policy.ForeignPolicyRefused):
            policy.assess_rules(table, {}, [])


class RenderTransitions(unittest.TestCase):
    """The committed render(): every deny drops only accept lines, in order."""

    CLIENT = {'schema': 'aegis_device_guard_binding_v1', 'boot_id': 'b' * 32, 'state_sha256': '0' * 64,
              'path': 'system.slice/aegis-auto@' + 'a' * 64 + '.service', 'inode': '1001',
              'invocation': 'a' * 32}
    MANAGER = dict(CLIENT, path='system.slice/systemd-networkd.service', inode='1002',
                   invocation='c' * 32)
    SCOPED = {'binding': {'interface': 'aegisacp0', 'listen_ipv4': '10.231.80.1', 'listen_port': 15080},
              'mark': 0x12345678, 'marker': 'aegis-auto-scoped-reply-' + 'c' * 64}

    def setUp(self):
        try:
            harness.bash()
        except harness.HarnessRefused:
            self.skipTest('bash >= 4 unavailable')

    def lines(self, profile, client, manager, scoped=False, local=False):
        code, out, err = harness.render(profile=profile, uplink='uplink0', management_ports='22',
                                        client=self.CLIENT if client else None,
                                        scoped=self.SCOPED if scoped else None,
                                        manager=self.MANAGER if manager else None, dhcp4='1', dhcp6='1',
                                        local_dnat=(('tcp', 15443), ('udp', 15553)) if local else None)
        self.assertEqual((code, err), (0, ''))
        self.assertNotIn(harness.REFUSED, out)
        return out.splitlines()

    @staticmethod
    def chain(lines, name):
        return [line for line in lines if line.split()[:5] == ['add', 'rule', 'inet', harness.TABLE, name]]

    def test_grant_to_deny_and_manager_removal(self):
        for profile in ('full-wide-tun', 'wide-redirect-safe', 'prerouting_scoped'):
            for scoped, local in ((False, False), (True, False), (False, True), (True, True)):
                deny_variants = ((self.lines(profile, False, True), True),
                                 (self.lines(profile, False, False), False))
                granted = self.lines(profile, True, True, scoped, local)
                for deny, with_manager in deny_variants:
                    with self.subTest(profile=profile, scoped=scoped, local=local, manager=with_manager):
                        self.assertEqual(granted[:6], deny[:6])  # table and the four chains
                        for name in ('incoming', 'output', 'forward', 'postroute'):
                            kept = iter(self.chain(granted, name))
                            for line in self.chain(deny, name):
                                for old in kept:
                                    if old == line:
                                        break
                                    self.assertRegex(old, r' accept( comment "[^"]+")?$')
                                else:
                                    self.fail('deny added or reordered: ' + line)
                            for old in kept:
                                self.assertRegex(old, r' accept( comment "[^"]+")?$')
                        self.assertEqual(self.chain(deny, 'output')[0],
                                         'add rule inet aegis_device_guard output meta mark '
                                         '{ 0xa361c001, 0xa361c002 } meta mark set 0')
                        for name in ('output', 'forward', 'postroute'):
                            self.assertTrue(self.chain(deny, name)[-1].endswith(' counter drop'))


@unittest.skipUnless(sys.platform == 'linux' and hasattr(os, 'geteuid') and os.geteuid() == 0 and
                     os.environ.get('AEGIS_RUN_KERNEL_STAND') == '1' and shutil.which('nft') and
                     shutil.which('unshare'), 'disposable Linux/root stand with nft')
class KernelRenderTransitions(unittest.TestCase):
    """Real render() batches in a private netns; real cgroupfs ids; real nft JSON."""

    def test_real_kernel_transitions_and_pruned_display(self):
        name = uuid.uuid4().hex[:12]
        client = 'system.slice/aegis-qa-r20-client-%s.service' % name
        manager = 'system.slice/aegis-qa-r20-manager-%s.service' % name
        root = Path('/sys/fs/cgroup')
        for path in (client, manager):
            (root / path).mkdir(parents=True)
        start(self, monitor, 'MANAGER_CGROUPS', new=monitor.MANAGER_CGROUPS | {manager})
        self.addCleanup(lambda: [(root / p).rmdir() for p in (client, manager) if (root / p).exists()])

        def binding(path, invocation):
            return dict(RenderTransitions.CLIENT, path=path, invocation=invocation)

        def listing(text, prune=''):
            with tempfile.NamedTemporaryFile('w', suffix='.nft') as batch:
                batch.write(text)
                batch.flush()
                script = 'nft -f "$1"; nft --json list ruleset; echo @@@@; ' \
                         'if [ -n "$2" ]; then rmdir "$2"; nft --json list ruleset; fi'
                result = subprocess.run(['unshare', '--net', '/bin/sh', '-ec', script, 'qa', batch.name, prune],
                                        capture_output=True, timeout=60, check=True)
            loaded, pruned = result.stdout.decode().split('@@@@\n')
            return items(loaded), (items(pruned) if prune else None)

        for profile in ('full-wide-tun', 'wide-redirect-safe'):
            def render(with_client, with_manager):
                code, out, err = harness.render(
                    profile=profile, uplink='lo', management_ports='22',
                    client=binding(client, 'a' * 32) if with_client else None, scoped=None,
                    manager=binding(manager, 'c' * 32) if with_manager else None, dhcp4='1', dhcp6='1')
                self.assertEqual((code, err), (0, ''))
                return out
            granted, _ = listing(render(True, True))
            baseline = monitor._guard_view(granted)
            self.assertIs(monitor.live_client_grant(granted), True)
            deny, _ = listing(render(False, True))
            self.assertIs(monitor.guard_loosened(deny, baseline), False)
            self.assertIs(monitor.live_client_grant(deny), False)
            _, pruned = listing(render(False, True), prune=str(root / manager))
            self.assertTrue(any(type(o) is str and o.isdigit() for o in GuardTripwire.operands(pruned)))
            self.assertIs(monitor.guard_loosened(pruned, baseline), False)
            (root / manager).mkdir()
            baseline = monitor._guard_view(listing(render(False, True))[0])
            final, _ = listing(render(False, False))
            self.assertIs(monitor.guard_loosened(final, baseline), False)
            self.assertIs(monitor.guard_loosened(granted, monitor._guard_view(final)), True)


if __name__ == '__main__':
    unittest.main()
