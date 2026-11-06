#!/usr/bin/env python3
"""Exercise the actual event loop's event-loss and bounded scheduling paths."""
import contextlib
import errno
import os
from pathlib import Path
import socket
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'lib'))
import aegis_auto_foreign_monitor as p


class Monitor(unittest.TestCase):
    def test_pinned_prejournal_watchdog_and_guardian_borrow_witness_only(self):
        from types import SimpleNamespace
        fd=os.open('/dev/null',os.O_RDONLY)
        try:
            actor=SimpleNamespace(JOURNAL=Path('/nonexistent-aegis-test-journal'))
            facts={'InvocationID':'a'*32,'ControlGroup':'/system.slice/actor'}
            with mock.patch.object(p.os.path,'lexists',return_value=False), \
                 mock.patch.object(p,'_witness_denied') as denied:
                for unit in ('aegis-auto-guardian.service',
                             'aegis-auto-guardian-watchdog.service'):
                    context=p._borrow_context(actor,unit,facts,fd,False)
                    self.assertTrue(context['witness_only'])
                    self.assertIsNone(context['private_unit'])
                    self.assertEqual(context['actor_unit'],unit)
                    os.close(context['actor_pidfd'])
                self.assertEqual(denied.call_count,2)
        finally:os.close(fd)

    def test_transition_pid1_facts_require_exact_loaded_source_and_scope(self):
        values={'LoadState':'loaded','ActiveState':'activating','SubState':'start',
                'Type':'oneshot','Result':'success','MainPID':'4242',
                'ControlPID':'0','InvocationID':'a'*32,
                'ControlGroup':'/system.slice/'+p.TRANSITION_UNIT,
                'FragmentPath':str(p.TRANSITION_UNIT_FILE),'DropInPaths':''}
        def read(*_argv):
            return '\n'.join(k+'='+v for k,v in values.items()).encode()+b'\n'
        with mock.patch.object(p,'run',side_effect=read):
            self.assertEqual(p._transition_facts(),values)
            for key,bad in (('Type','simple'),
                            ('DropInPaths','/tmp/override.conf'),
                            ('FragmentPath','/tmp/foreign.service'),
                            ('ControlGroup','/system.slice/foreign.service'),
                            ('InvocationID','unknown')):
                with self.subTest(key=key):
                    old=values[key];values[key]=bad
                    with self.assertRaises(ValueError):p._transition_facts()
                    values[key]=old

    def test_transition_pidfd_exit_waits_for_same_pid1_publication(self):
        before={'LoadState':'loaded','ActiveState':'activating','SubState':'start',
                'Type':'oneshot','Result':'success','MainPID':'4242',
                'ControlPID':'0','InvocationID':'a'*32,
                'ControlGroup':'/system.slice/'+p.TRANSITION_UNIT,
                'FragmentPath':str(p.TRANSITION_UNIT_FILE),'DropInPaths':''}
        self.assertFalse(p._transition_publication(before,before))
        publishing={**before,'MainPID':'0'}
        self.assertFalse(p._transition_publication(before,publishing))
        published={**publishing,'ActiveState':'active','SubState':'exited',
                   'ControlGroup':''}
        self.assertTrue(p._transition_publication(before,published))
        for changed in ({**published,'InvocationID':'b'*32},
                        {**published,'ControlGroup':'/system.slice/foreign.service'},
                        {**published,'ControlPID':'5252'},
                        {**published,'MainPID':'5252'},
                        {**published,'Type':'simple'},
                        {**published,'SubState':'running'},
                        {**published,'ActiveState':'failed'},
                        {**published,'Result':'exit-code'},
                        {**before,'ControlPID':'5252'},
                        {**before,'ControlGroup':''},
                        {**before,'MainPID':'5252'},
                        {**before,'SubState':'start-post'}):
            with self.subTest(changed=changed):
                with self.assertRaises(ValueError):p._transition_publication(before,changed)

    def test_transition_pid1_empty_cgroup_only_after_successful_oneshot_exit(self):
        values={'LoadState':'loaded','ActiveState':'active','SubState':'exited',
                'Type':'oneshot','Result':'success','MainPID':'0','ControlPID':'0',
                'InvocationID':'a'*32,'ControlGroup':'',
                'FragmentPath':str(p.TRANSITION_UNIT_FILE),'DropInPaths':''}
        def read(*_argv):
            return '\n'.join(k+'='+v for k,v in values.items()).encode()+b'\n'
        with mock.patch.object(p,'run',side_effect=read):
            self.assertEqual(p._transition_facts(),values)
            for key,bad in (('ActiveState','activating'),('SubState','start'),
                            ('Type','simple'),('Result','exit-code'),
                            ('MainPID','4242'),('ControlPID','4242'),
                            ('ControlGroup','/system.slice/foreign.service')):
                with self.subTest(key=key):
                    old=values[key];values[key]=bad
                    with self.assertRaises(ValueError):p._transition_facts()
                    values[key]=old

    def test_transition_pidfd_death_during_pid1_read_admits_only_same_publication(self):
        before={'LoadState':'loaded','ActiveState':'activating','SubState':'start',
                'Type':'oneshot','Result':'success','MainPID':'4242','ControlPID':'0',
                'InvocationID':'a'*32,
                'ControlGroup':'/system.slice/'+p.TRANSITION_UNIT,
                'FragmentPath':str(p.TRANSITION_UNIT_FILE),'DropInPaths':''}
        completed={**before,'ActiveState':'active','SubState':'exited',
                   'MainPID':'0','ControlGroup':''}
        publishing={**before,'MainPID':'0'}
        self.assertFalse(p._transition_sample_after_read(before,before,True))
        self.assertTrue(p._transition_sample_after_read(before,publishing,False))
        self.assertTrue(p._transition_sample_after_read(before,completed,False))
        for changed,alive in ((publishing,True),(completed,True),
                              ({**completed,'InvocationID':'b'*32},False),
                              ({**completed,'ControlPID':'4242'},False),
                              ({**completed,'ControlGroup':'/system.slice/foreign.service'},False)):
            with self.subTest(changed=changed,alive=alive):
                with self.assertRaises(ValueError):
                    p._transition_sample_after_read(before,changed,alive)

    def test_transition_wait_rejects_wrong_oneshot_pid_role_before_source(self):
        from types import SimpleNamespace
        good={'ActiveState':'activating','SubState':'start',
              'MainPID':'4242','ControlPID':'0'}
        for wrong in ({**good,'ControlPID':'4242'},
                      {**good,'MainPID':'0'},
                      {**good,'MainPID':'foreign'},
                      {**good,'SubState':'start-pre'},
                      {**good,'ActiveState':'active'}):
            with self.subTest(wrong=wrong), \
                 mock.patch.object(p,'actor_module',return_value=SimpleNamespace()), \
                 mock.patch.object(p,'_transition_facts',return_value=wrong), \
                 mock.patch.object(p,'_transition_source') as source:
                with self.assertRaises(p.LeaseUnavailable):
                    p._wait_authenticated_transition(-1,None)
                source.assert_not_called()

    def test_boot_monitor_waits_for_oneshot_without_dependency_cycle(self):
        root=Path(__file__).resolve().parents[2]
        monitor=(root/'packaging/systemd/aegis-foreign-policy-monitor.service').read_text()
        transition=(root/'packaging/systemd/aegis-auto-terminal-transition.service').read_text()
        self.assertIn('After=local-fs.target ufw.service aegis-device-egress-guard.service '
                      'aegis-auto-guardian-watchdog.service aegis-auto-terminal-transition.service',monitor)
        self.assertIn('Before=aegis-auto-guardian.service network-pre.target',transition)
        self.assertNotIn('aegis-foreign-policy-monitor.service',transition)

    def test_authenticated_transition_mutation_blocks_before_and_after_stop(self):
        from types import SimpleNamespace
        actions=[]
        def command(argv,**_kwargs):
            actions.append(tuple(argv))
            return SimpleNamespace(returncode=0)
        actor=SimpleNamespace(_alive=lambda _fd:False)
        with mock.patch.object(p,'publish_drift',side_effect=lambda *_:actions.append(('drift',))), \
             mock.patch.object(p.subprocess,'run',side_effect=command), \
             mock.patch.object(p,'actor_module',return_value=actor), \
             mock.patch.object(p,'_witness_denied'), \
             mock.patch.object(p,'_isolated_deny_policy_sha',return_value=('a','b')), \
             mock.patch.object(p,'state',return_value=(b'',{'uplink':'eth0'})), \
             mock.patch.object(p,'assess_foreign_policy',side_effect=ValueError('foreign ACCEPT')) as foreign, \
             mock.patch.object(p,'stop_owned_units',side_effect=lambda *_:actions.append(('clients',)) or True):
            p._revoke_borrowed_transition(17,19)
            foreign.assert_not_called()  # the sticky unsafe rule is not admitted
        self.assertEqual(actions[0],('drift',))
        self.assertEqual(actions[1],('/bin/bash',p.HELPER,'block'))
        self.assertEqual(actions[2],('clients',))
        self.assertEqual(actions[3],('systemctl','stop',p.TRANSITION_UNIT))
        self.assertEqual(actions[4],('/bin/bash',p.HELPER,'block'))
        self.assertEqual(actions[5],('clients',))

    def test_transition_revoke_never_accepts_failed_stop_or_block(self):
        from types import SimpleNamespace
        actor=SimpleNamespace(_alive=lambda _fd:True)
        with mock.patch.object(p,'publish_drift'), \
             mock.patch.object(p.subprocess,'run',return_value=SimpleNamespace(returncode=0)), \
             mock.patch.object(p,'actor_module',return_value=actor), \
             mock.patch.object(p,'_witness_denied'), \
             mock.patch.object(p,'_isolated_deny_policy_sha',return_value=('a','b')), \
             mock.patch.object(p,'state',return_value=(b'',{'uplink':'eth0'})), \
             mock.patch.object(p,'stop_owned_units',return_value=True):
            with self.assertRaises(ValueError):p._revoke_borrowed_transition(17,19)

    def test_emergency_force_block_bypasses_both_no_write_shortcuts(self):
        helper=(Path(__file__).resolve().parents[1]/'aegis-device-egress-guard.sh').read_text()
        self.assertEqual(helper.count('"${AEGIS_AUTO_FORCE_BLOCK:-}" != 1 &&'),2)
        self.assertIn("'AEGIS_AUTO_FORCE_BLOCK':'1'",
                      (Path(__file__).resolve().parents[1]/'lib'/'aegis_auto_foreign_monitor.py').read_text())

    @unittest.skipUnless(__import__('os').geteuid()==0,'root-owned kernel flock fixture')
    def test_exact_transition_completion_reacquires_before_snapshot(self):
        import fcntl,tempfile
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'guard.lock';held=os.open(path,os.O_RDWR|os.O_CREAT|os.O_EXCL,0o600)
            try:
                fcntl.flock(held,fcntl.LOCK_EX|fcntl.LOCK_NB)
                def completed(_fd,_original):
                    fcntl.flock(held,fcntl.LOCK_UN)
                with mock.patch.object(p,'LOCK',path), \
                     mock.patch.object(p,'borrow_actor_guard',side_effect=p.LeaseUnavailable), \
                     mock.patch.object(p,'_wait_authenticated_transition',side_effect=completed) as wait:
                    with p.guard_lock() as received:
                        self.assertIsNone(p._BORROW_CONTEXT)
                        self.assertEqual(os.fstat(received).st_ino,os.fstat(held).st_ino)
                    wait.assert_called_once()
                fcntl.flock(held,fcntl.LOCK_EX|fcntl.LOCK_NB)
            finally:os.close(held)

    @unittest.skipUnless(__import__('os').geteuid()==0,'root-owned kernel flock fixture')
    def test_unknown_new_writer_after_transition_stays_sticky(self):
        import fcntl,tempfile
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'guard.lock';held=os.open(path,os.O_RDWR|os.O_CREAT|os.O_EXCL,0o600)
            try:
                fcntl.flock(held,fcntl.LOCK_EX|fcntl.LOCK_NB)
                with mock.patch.object(p,'LOCK',path), \
                     mock.patch.object(p,'borrow_actor_guard',side_effect=p.LeaseUnavailable), \
                     mock.patch.object(p,'_wait_authenticated_transition'), \
                     mock.patch.object(p,'publish_drift') as sticky, \
                     mock.patch.object(p,'stop_owned_units',return_value=True) as stops:
                    with self.assertRaises(p.LeaseUnavailable):
                        with p.guard_lock():self.fail('unknown successor writer admitted')
                    sticky.assert_called_once_with(True)
                    stops.assert_called_once()
            finally:os.close(held)

    def test_installed_manager_ready_control_helpers_can_lend_only_original_ofd(self):
        """Portable protocol control; real PID1/pidfd proof has its own Linux fixture."""
        import fcntl
        from types import SimpleNamespace
        real_stat, real_text, real_bytes, real_iter = os.stat, Path.read_text, Path.read_bytes, Path.iterdir
        for manager in ('NetworkManager.service', 'systemd-networkd.service'):
            for action, root_uid in ((b'bind-manager', True), (b'manager-ready', True),
                                     (b'unknown-ready', True), (b'manager-ready', False)):
                with self.subTest(manager=manager, action=action, root_uid=root_uid), tempfile.TemporaryDirectory() as folder:
                    lock = Path(folder)/'guard.lock'
                    held = os.open(lock, os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600)
                    fcntl.flock(held, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    identity = os.fstat(held)
                    def guard_identity(fd):
                        value = os.fstat(fd)
                        self.assertEqual((value.st_dev,value.st_ino), (identity.st_dev,identity.st_ino))
                    actor = SimpleNamespace(Refused=RuntimeError, _alive=lambda _fd:True,
                        _pidfd_pid=lambda _fd:4242, _guard_identity=guard_identity)
                    facts = {'ControlPID':'4242','MainPID':'4241','ActiveState':'activating',
                        'InvocationID':'a'*32, 'ControlGroup':'/system.slice/'+manager}
                    def unit_facts(unit):
                        if unit != manager:raise ValueError('not this actor')
                        return facts
                    def text(path, *args, **kwargs):
                        if str(path)=='/proc/4242/status':
                            return 'Uid:\t0\t0\t0\t0\n' if root_uid else 'Uid:\t1\t1\t1\t1\n'
                        if str(path)=='/proc/4242/cgroup':return '0::/system.slice/'+manager+'\n'
                        return real_text(path,*args,**kwargs)
                    def raw(path, *args, **kwargs):
                        if str(path)=='/proc/4242/cmdline':
                            return b'/bin/bash\0'+p.HELPER.encode()+b'\0'+action+b'\0'
                        return real_bytes(path,*args,**kwargs)
                    def stat_path(path, *args, **kwargs):
                        if str(path) in ('/proc/4242/ns/net','/proc/self/ns/net'):
                            return SimpleNamespace(st_ino=1234)
                        return real_stat(path,*args,**kwargs)
                    descriptor = SimpleNamespace(name='9', stat=lambda:os.fstat(held))
                    def descriptors(path):
                        return iter((descriptor,)) if str(path)=='/proc/4242/fd' else real_iter(path)
                    library = SimpleNamespace(pidfd_getfd=mock.Mock(side_effect=lambda *_args:os.dup(held)))
                    borrowed = context = None
                    try:
                        with mock.patch.object(p,'LOCK',lock), \
                             mock.patch.object(p,'_borrow_rotation_guard',return_value=None), \
                             mock.patch.object(p,'actor_module',return_value=actor), \
                             mock.patch.object(p,'state',return_value=(b'',{'manager':manager})), \
                             mock.patch.object(p,'_actor_facts',side_effect=unit_facts), \
                             mock.patch.object(p.ctypes,'CDLL',return_value=library), \
                             mock.patch.object(p.os,'pidfd_open',create=True,
                                               side_effect=lambda *_args:os.open(lock,os.O_RDONLY)), \
                             mock.patch.object(Path,'read_text',text), \
                             mock.patch.object(Path,'read_bytes',raw), \
                             mock.patch.object(Path,'iterdir',descriptors), \
                             mock.patch.object(p.os,'stat',stat_path):
                            if action==b'unknown-ready' or not root_uid:
                                with self.assertRaises(p.LeaseUnavailable):p.borrow_actor_guard()
                                library.pidfd_getfd.assert_not_called()
                            else:
                                borrowed, context = p.borrow_actor_guard()
                                self.assertEqual(context['actor_unit'], manager)
                                self.assertTrue(context['transient'])
                                library.pidfd_getfd.assert_called_once()
                                # A borrowed locked OFD with no authenticated
                                # context must never be treated as ours.
                                with mock.patch.object(p,'_borrow_context',return_value=None):
                                    with self.assertRaises(p.LeaseUnavailable):p.borrow_actor_guard()
                        other = os.open(lock,os.O_RDONLY)
                        try:
                            with self.assertRaises(BlockingIOError):
                                fcntl.flock(other,fcntl.LOCK_EX | fcntl.LOCK_NB)
                        finally:os.close(other)
                    finally:
                        if borrowed is not None:os.close(borrowed)
                        if context is not None:os.close(context['actor_pidfd'])
                        os.close(held)

    def setUp(self):
        # Contended-lock tests exercise an AUTO v2 lease. Give the monitor a
        # real trusted v2 state so its ordinary-v1 branch cannot be selected
        # by an absent installed host state in the disposable Linux fixture.
        if sys.platform != 'linux' or os.geteuid() != 0:
            return
        temporary = tempfile.TemporaryDirectory(prefix='aegis-monitor-v2-', dir='/run')
        self.addCleanup(temporary.cleanup)
        state = Path(temporary.name) / 'device-guard.conf'
        state.write_bytes(b'schema=aegis_device_guard_v2\n')
        state.chmod(0o600)
        patcher = mock.patch.object(p, 'STATE', state)
        patcher.start()
        self.addCleanup(patcher.stop)

    @unittest.skipUnless(sys.platform == 'linux' and os.geteuid() == 0,
                         'root Linux flock fixture')
    def test_real_v1_state_waits_for_ordinary_writer_without_auto_borrow(self):
        import fcntl
        import threading

        state = p.STATE.parent / 'ordinary-v1.conf'
        state.write_bytes(b'\n'.join((
            b'schema=aegis_device_guard_v1', b'armed=1',
            b'service=aegis-client.service', b'uplink=fixture0',
            b'manager=networking.service', b'capture_interface=aegis-tun0',
            b'management_ipv4=198.18.1.1', b'management_ipv6=',
            b'management_ports=22', b'dhcp4=0', b'dhcp6=0',
            b'initramfs_network=absent_verified', b'')))
        state.chmod(0o600)
        lock = state.parent / 'guard.lock'
        lock.touch(mode=0o600)
        held = os.open(lock, os.O_RDONLY)
        release = threading.Timer(0.05, fcntl.flock,
                                  args=(held, fcntl.LOCK_UN))
        try:
            fcntl.flock(held, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with mock.patch.object(p, 'STATE', state), \
                 mock.patch.object(p, 'LOCK', lock), \
                 mock.patch.object(p, '_ordinary_v1_writer_alive', return_value=True), \
                 mock.patch.object(p, 'borrow_actor_guard',
                                   side_effect=AssertionError('AUTO borrow used')):
                self.assertTrue(p._ordinary_v1_without_auto_lease())
                release.start()
                with p.guard_lock() as received:
                    self.assertEqual(os.fstat(received).st_ino, lock.stat().st_ino)
                (state.parent / 'auto-guardian-install.json').write_text('{}')
                with self.assertRaisesRegex(ValueError, 'overlaps an AUTO lease'):
                    p._ordinary_v1_without_auto_lease()
        finally:
            if release.ident is not None:
                release.join(timeout=1)
            os.close(held)

    @unittest.skipUnless(hasattr(__import__('os'),'pidfd_open'),'Linux PIDFD')
    def test_proc_exit_wait_uses_real_pidfd_without_borrowing_authority(self):
        import os,select,subprocess
        from types import SimpleNamespace
        def alive(fd):
            watcher=select.poll();watcher.register(fd,select.POLLIN)
            return not watcher.poll(0)
        child=subprocess.Popen(['/bin/sleep','0.03'])
        fd=os.pidfd_open(child.pid,0)
        try:
            self.assertTrue(p._completed_actor_after_proc_error(SimpleNamespace(_alive=alive),fd))
            child.wait(timeout=2)
        finally:
            os.close(fd)
            if child.poll()is None:child.kill();child.wait(timeout=2)

    def test_proc_error_waits_only_for_kernel_proven_actor_exit(self):
        import select
        from types import SimpleNamespace
        watcher=mock.Mock();watcher.poll.return_value=[(9,select.POLLIN)]
        actor=SimpleNamespace(_alive=mock.Mock(side_effect=[True,False]))
        with mock.patch.object(p.select,'poll',return_value=watcher):
            self.assertTrue(p._completed_actor_after_proc_error(actor,9))
        watcher.poll.assert_called_once_with(200)
        actor._alive.side_effect=[True,True]
        watcher.reset_mock()
        with mock.patch.object(p.select,'poll',return_value=watcher):
            self.assertFalse(p._completed_actor_after_proc_error(actor,9))
        watcher.poll.assert_called_once_with(200)

    def test_watchdog_ready_transition_keeps_exact_borrowed_owner(self):
        import json
        from types import SimpleNamespace
        before={'ActiveState':'activating','MainPID':'123','ControlPID':'0',
                'InvocationID':'a'*32,
                'ControlGroup':'/system.slice/aegis-auto-guardian-watchdog.service'}
        after=dict(before,ActiveState='active')
        context={'actor_unit':'aegis-auto-guardian-watchdog.service',
                 'actor_pidfd':9,'actor_facts':before,'private_unit':'owned',
                 'private_invocation':'b'*32,'private_main_pid':456}
        actor=SimpleNamespace(JOURNAL=Path('/unused'),_alive=mock.Mock(return_value=True),
                              _guard_identity=mock.Mock())
        journal={'boot_id':'boot','private_unit':'owned','invocation_id':'b'*32,'private_main_pid':456}
        with mock.patch.object(p,'trusted_read',return_value=json.dumps(journal).encode()):
            with mock.patch.object(p.Path,'read_text',return_value='boot'):
                p._borrowed_actor_stable(actor,context,after,7)
                self.assertTrue(p._same_actor_or_watchdog_ready(context['actor_unit'],before,after))
                self.assertFalse(p._same_actor_or_watchdog_ready('aegis-auto-guardian.service',before,after))
                self.assertFalse(p._same_actor_or_watchdog_ready(context['actor_unit'],after,before))
            actor._guard_identity.assert_called_once_with(7)
            for changed in (dict(after,MainPID='999'),dict(after,InvocationID='c'*32),
                            dict(after,ControlPID='7'),dict(after,ActiveState='deactivating')):
                with self.assertRaises(ValueError):
                    p._borrowed_actor_stable(actor,context,changed,7)
            actor._alive.return_value=False
            with self.assertRaises(ValueError):
                p._borrowed_actor_stable(actor,context,after,7)
        actor._alive.return_value=True
        with mock.patch.object(p,'trusted_read',return_value=json.dumps(
                dict(journal,private_main_pid=999)).encode()):
            with mock.patch.object(p.Path,'read_text',return_value='boot'):
                with self.assertRaises(ValueError):
                    p._borrowed_actor_stable(actor,context,after,7)

    def test_refusal_coordinates_never_include_exception_contents(self):
        try:raise ValueError('PRIVATE_SENTINEL parser bytes')
        except ValueError as error:value=p.refusal_coordinates(error)
        self.assertEqual(value,{'event':'foreign_policy_refused','source':'unknown','line':0})
        self.assertNotIn('PRIVATE_SENTINEL',str(value))

    def test_snapshot_diagnostics_are_closed_and_do_not_add_a_retry(self):
        error=p.PolicySnapshotChanged({'nftables':[]},
            {'nftables':[{'PRIVATE_SENTINEL':{'secret':'private-rule'}}]})
        error.generation_before=7;error.generation_after=7
        report=p.refusal_coordinates(error)
        self.assertEqual(report['snapshot_first_kind'],'absent')
        self.assertEqual(report['snapshot_second_kind'],'unknown')
        self.assertEqual(report['generation_before'],7)
        self.assertEqual(report['generation_after'],7)
        self.assertNotIn('PRIVATE_SENTINEL',str(report))
        self.assertNotIn('private-rule',str(report))
        with mock.patch.object(p,'guard_lock',side_effect=lambda **_:contextlib.nullcontext()), \
             mock.patch.object(p,'link_identities',return_value=frozenset()), \
             mock.patch.object(p,'get_generation',return_value=7), \
             mock.patch.object(p,'state',return_value=(b'',{'armed':'1','uplink':'eth0'})), \
             mock.patch.object(p,'assessment_options',return_value={}), \
             mock.patch.object(p,'assess_foreign_policy',side_effect=error)as read, \
             mock.patch.object(p.time,'sleep')as pause:
            with self.assertRaises(p.PolicySnapshotChanged):p.stable_assessment(None)
            read.assert_called_once();pause.assert_not_called()

    def test_prejournal_guardian_admits_only_trace_with_no_client_candidate(self):
        import os,re,tempfile
        from types import SimpleNamespace
        with tempfile.TemporaryDirectory() as tmp:
            actor=SimpleNamespace(JOURNAL=Path(tmp)/'pending.json',
                PRIVATE=re.compile(r'aegis-auto@[a-f0-9]{64}\.service'))
            read,write=os.pipe()
            try:
                with mock.patch.object(p,'STATE',Path(tmp)/'guard.conf'):
                    context=p._borrow_context(actor,'aegis-auto-guardian.service',{},read,False)
                    self.assertTrue(context['witness_only'])
                    self.assertIsNone(context['private_unit'])
                    try:
                        with mock.patch.object(p,'_BORROW_CONTEXT',context), \
                             mock.patch.object(p,'actor_module',return_value=actor):
                            self.assertEqual(p.assessment_options({}),{'allow_active_trace':True})
                    finally:os.close(context['actor_pidfd'])
                    watchdog=p._borrow_context(actor,'aegis-auto-guardian-watchdog.service',{},read,False)
                    self.assertTrue(watchdog['witness_only'])
                    self.assertIsNone(watchdog['private_unit'])
                    os.close(watchdog['actor_pidfd'])
            finally:os.close(read);os.close(write)

    def test_prejournal_trace_refuses_client_binding_and_dangling_journal(self):
        import os,re,tempfile
        from types import SimpleNamespace
        with tempfile.TemporaryDirectory() as tmp:
            state=Path(tmp)/'guard.conf';binding=Path(str(state)+'.client-binding')
            actor=SimpleNamespace(JOURNAL=Path(tmp)/'pending.json',
                PRIVATE=re.compile(r'aegis-auto@[a-f0-9]{64}\.service'))
            read,write=os.pipe()
            try:
                with mock.patch.object(p,'STATE',state), \
                     mock.patch.object(p,'trusted_read',side_effect=lambda path,*_:Path(path).read_bytes()):
                    for dangling in (False,True):
                        if dangling:binding.symlink_to(Path(tmp)/'absent')
                        else:binding.write_bytes(b'client')
                        with self.assertRaises(ValueError):
                            p._borrow_context(actor,'aegis-auto-guardian.service',{},read,False)
                        with mock.patch.object(p,'_BORROW_CONTEXT',{'witness_only':True}), \
                             mock.patch.object(p,'actor_module',return_value=actor), \
                             self.assertRaises(ValueError):p.assessment_options({})
                        binding.unlink()
                    actor.JOURNAL.symlink_to(Path(tmp)/'missing')
                    with self.assertRaises(OSError):
                        p._borrow_context(actor,'aegis-auto-guardian.service',{},read,False)
            finally:os.close(read);os.close(write)

    def test_prejournal_promotion_requires_current_boot_and_typed_private_unit(self):
        import json,re,tempfile
        from types import SimpleNamespace
        with tempfile.TemporaryDirectory() as tmp:
            actor=SimpleNamespace(JOURNAL=Path(tmp)/'pending.json',
                PRIVATE=re.compile(r'aegis-auto@[a-f0-9]{64}\.service'))
            unit='aegis-auto@'+'a'*64+'.service'
            context={'witness_only':True,'private_unit':None}
            with mock.patch.object(p,'_BORROW_CONTEXT',context), \
                 mock.patch.object(p,'actor_module',return_value=actor), \
                 mock.patch.object(p,'trusted_read',side_effect=lambda path,*_:Path(path).read_bytes()), \
                 mock.patch.object(Path,'read_text',return_value='current-boot'), \
                 mock.patch.object(p,'state',return_value=(b'guard',{'manager':'systemd-networkd.service'})), \
                 mock.patch.object(p,'run',return_value=b'ActiveState=inactive\nControlGroup=\n'):
                for boot,private in [('old-boot',unit),('current-boot','foreign.service')]:
                    actor.JOURNAL.write_text(json.dumps({'boot_id':boot,'private_unit':private}))
                    with self.assertRaises(ValueError):p.assessment_options({'manager':'systemd-networkd.service'})
                    self.assertTrue(context['witness_only'])
                actor.JOURNAL.write_text(json.dumps({'boot_id':'current-boot','private_unit':unit}))
                options=p.assessment_options({'manager':'systemd-networkd.service'})
                self.assertTrue(options['allow_active_trace'])
                self.assertNotIn('witness_only',context)
                self.assertEqual(context['private_unit'],unit)
                self.assertTrue(all(pair['client']is None for pair in options['binding_candidates']))

    def drive(self,kind):
        clock=[0.0];created=[];checks=[];binds=[]
        class Socket:
            def __init__(self,*_):created.append(self)
            def bind(self,a):binds.append((self,a))
            def recvmsg(self,_):
                if kind=='enobufs':raise OSError(errno.ENOBUFS,'dropped')
                if kind=='socket_error':raise OSError(errno.EIO,'failed')
                return b'event',[],0,None
        def select(read,*args):
            timeout=args[-1]
            if not checks:return [],[],[]
            if kind=='periodic':
                clock[0]+=timeout
                return [],[],[]
            clock[0]+=min(timeout,0.005)
            return [created[0]],[],[]
        def state():
            return b'',{'armed':'0' if len(checks)>=3 else '1','uplink':'eth0'}
        def assess(*a,**k):
            self.assertEqual(len(binds),3,'all subscriptions must precede snapshot')
            self.assertIs(k.get('require_guard'),True,'missing guard must not be admitted')
            self.assertIs(k.get('allow_stopped_local_display_transition'),True,
                          'only the guarded monitor may request the stopped display proof')
            checks.append(clock[0]);return {'foreign_projection_sha256':'a'*64}
        with mock.patch.object(p.socket,'AF_NETLINK',16,create=True),\
             mock.patch.object(p.socket,'SOCK_NONBLOCK',0x800,create=True),\
             mock.patch.object(p.os,'geteuid',return_value=0),\
             mock.patch.object(p.socket,'socket',side_effect=Socket),\
             mock.patch.object(p.select,'select',side_effect=select),\
             mock.patch.object(p.time,'monotonic',side_effect=lambda:clock[0]),\
             mock.patch.object(p,'guard_lock',side_effect=lambda **_kwargs:contextlib.nullcontext()),\
             mock.patch.object(p,'get_generation',return_value='g'),\
             mock.patch.object(p,'state',side_effect=state),\
             mock.patch.object(p,'assess_foreign_policy',side_effect=assess),\
             mock.patch.object(p,'cgroup_members'):
            p.monitor()
        return checks

    def test_leading_edge_storm_cannot_postpone_snapshot(self):
        checks=self.drive('storm')
        self.assertEqual(checks[0],0)
        self.assertLessEqual(checks[1],0.106)
        self.assertLessEqual(checks[2]-checks[1],0.106)

    def test_enobufs_forces_immediate_full_assessment(self):
        self.assertLessEqual(self.drive('enobufs')[1],0.005)

    def test_other_socket_errors_also_force_assessment(self):
        self.assertLessEqual(self.drive('socket_error')[1],0.005)

    def test_no_events_still_poll_every_second(self):
        self.assertEqual(self.drive('periodic'),[0.0,1.0,2.0])

    def test_pinned_actor_loader_registers_dataclass_identity_and_refuses_new_generation(self):
        import hashlib,json,sys
        raw=b'from dataclasses import dataclass\ndef _own_source(): return {}\n@dataclass\nclass Fixture: value: int\n'
        def read(path,*_):
            if str(path).endswith('auto-guardian-install.json'):
                return json.dumps({'watchdog_sha256':hashlib.sha256(raw).hexdigest()}).encode()
            return raw
        name='aegis_foreign_monitor_watchdog'
        original=sys.modules.pop(name,None)
        try:
            with mock.patch.object(p,'_ACTOR_MODULE',None),mock.patch.object(p,'trusted_read',side_effect=read):
                loaded=p.actor_module();self.assertIs(sys.modules[name],loaded)
                self.assertEqual(loaded.Fixture(7).value,7)
                self.assertIs(p.actor_module(),loaded)
                raw+=b'# changed generation\n'
                with self.assertRaisesRegex(ValueError,'generation changed'):p.actor_module()
        finally:
            sys.modules.pop(name,None)
            if original is not None:sys.modules[name]=original

    @unittest.skipUnless(__import__('os').geteuid()==0,'root-owned kernel flock fixture')
    def test_borrowed_original_ofd_does_not_unlock_or_reacquire_active_lease(self):
        import os,tempfile,fcntl
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'guard.lock';held=os.open(path,os.O_RDWR|os.O_CREAT|os.O_EXCL,0o600)
            try:
                fcntl.flock(held,fcntl.LOCK_EX|fcntl.LOCK_NB)
                with mock.patch.object(p,'LOCK',path), \
                     mock.patch.object(p,'borrow_actor_guard',side_effect=lambda:(os.dup(held),None)) as borrow:
                    with p.guard_lock() as received:
                        self.assertEqual(os.fstat(received).st_ino,os.fstat(held).st_ino)
                        fcntl.flock(received,fcntl.LOCK_EX|fcntl.LOCK_NB)
                    borrow.assert_called_once()
                other=os.open(path,os.O_RDONLY)
                try:
                    with self.assertRaises(BlockingIOError):fcntl.flock(other,fcntl.LOCK_EX|fcntl.LOCK_NB)
                finally:os.close(other)
            finally:os.close(held)
            other=os.open(path,os.O_RDONLY)
            try:fcntl.flock(other,fcntl.LOCK_EX|fcntl.LOCK_NB)
            finally:os.close(other)

    @unittest.skipUnless(__import__('os').geteuid()==0,'root-owned kernel flock fixture')
    def test_finished_writer_is_exclusive_before_snapshot_without_borrow(self):
        import os,tempfile,fcntl
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'guard.lock';held=os.open(path,os.O_RDWR|os.O_CREAT|os.O_EXCL,0o600)
            try:
                fcntl.flock(held,fcntl.LOCK_EX|fcntl.LOCK_NB)
                def finished():
                    fcntl.flock(held,fcntl.LOCK_UN)
                    raise p.LeaseUnavailable()
                with mock.patch.object(p,'LOCK',path),mock.patch.object(p,'borrow_actor_guard',side_effect=finished):
                    with p.guard_lock() as received:
                        self.assertIsNone(p._BORROW_CONTEXT)
                        self.assertEqual(os.fstat(received).st_ino,os.fstat(held).st_ino)
                        with self.assertRaises(BlockingIOError):fcntl.flock(held,fcntl.LOCK_EX|fcntl.LOCK_NB)
                fcntl.flock(held,fcntl.LOCK_EX|fcntl.LOCK_NB)
            finally:os.close(held)

    @unittest.skipUnless(__import__('os').geteuid()==0,'root-owned kernel flock fixture')
    def test_live_unknown_writer_and_replaced_inode_still_refuse(self):
        import os,tempfile,fcntl
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'guard.lock';held=os.open(path,os.O_RDWR|os.O_CREAT|os.O_EXCL,0o600)
            try:
                fcntl.flock(held,fcntl.LOCK_EX|fcntl.LOCK_NB)
                with mock.patch.object(p,'LOCK',path), \
                     mock.patch.object(p,'borrow_actor_guard',side_effect=p.LeaseUnavailable), \
                     mock.patch.object(p,'_wait_authenticated_transition',side_effect=p.LeaseUnavailable), \
                     mock.patch.object(p,'publish_drift') as sticky, \
                     mock.patch.object(p,'stop_owned_units',return_value=True) as stops:
                    with self.assertRaises(p.LeaseUnavailable):
                        with p.guard_lock():self.fail('live unknown holder admitted')
                    sticky.assert_called_once_with(True)
                    stops.assert_called_once()
                def replaced():
                    fcntl.flock(held,fcntl.LOCK_UN);path.rename(path.with_name('retained-original'))
                    fd=os.open(path,os.O_RDWR|os.O_CREAT|os.O_EXCL,0o600);os.close(fd)
                    raise p.LeaseUnavailable()
                with mock.patch.object(p,'LOCK',path),mock.patch.object(p,'borrow_actor_guard',side_effect=replaced):
                    with self.assertRaisesRegex(ValueError,'lock changed'):
                        with p.guard_lock():self.fail('replacement admitted')
            finally:os.close(held)

    @unittest.skipUnless(hasattr(__import__('os'), 'pidfd_open'), 'Linux PIDFD')
    def test_dead_pid1_candidate_does_not_create_authority_or_hide_live_writer(self):
        import os, subprocess, tempfile, fcntl
        child=subprocess.Popen(['/bin/true']);pid=child.pid;child.wait(timeout=5)
        facts={'MainPID':str(pid),'ControlPID':str(pid)}
        with mock.patch.object(p,'_borrow_rotation_guard',return_value=None), \
             mock.patch.object(p,'actor_module'), \
             mock.patch.object(p,'state',return_value=(b'',{'manager':'systemd-networkd.service'})), \
             mock.patch.object(p,'_actor_facts',return_value=facts):
            # Real ESRCH, rather than a manufactured validation exception.
            with self.assertRaises(p.LeaseUnavailable):p.borrow_actor_guard()
            with tempfile.TemporaryDirectory() as tmp:
                path=Path(tmp)/'guard.lock';held=os.open(path,os.O_RDWR|os.O_CREAT|os.O_EXCL,0o600)
                try:
                    fcntl.flock(held,fcntl.LOCK_EX|fcntl.LOCK_NB)
                    if os.geteuid()==0:
                        with mock.patch.object(p,'LOCK',path), \
                             mock.patch.object(p,'_wait_authenticated_transition',side_effect=p.LeaseUnavailable), \
                             mock.patch.object(p,'publish_drift'), \
                             mock.patch.object(p,'stop_owned_units',return_value=True), \
                             self.assertRaises(p.LeaseUnavailable):
                            with p.guard_lock():self.fail('unknown live writer admitted')
                finally:os.close(held)
            with mock.patch.object(p.os,'pidfd_open',side_effect=PermissionError('PRIVATE_SENTINEL')):
                with self.assertRaises(PermissionError):p.borrow_actor_guard()

    @unittest.skipUnless(hasattr(__import__('os'),'pidfd_open') and __import__('os').geteuid()==0,'Linux root PIDFD/flock')
    def test_actor_exit_after_pidfd_open_or_during_proc_read_requires_exclusive_original_inode(self):
        import os,subprocess,tempfile,fcntl,select,re
        from types import SimpleNamespace
        def alive(fd):
            poll=select.poll();poll.register(fd,select.POLLIN);return not poll.poll(0)
        actor=SimpleNamespace(Refused=RuntimeError,_alive=alive,
            _pidfd_pid=lambda fd:int(re.search(r'^Pid:\s*([0-9]+)',Path('/proc/self/fdinfo/'+str(fd)).read_text(),re.M)[1]))
        for when in ('after_open','during_proc'):
            with tempfile.TemporaryDirectory()as folder:
                path=Path(folder)/'guard.lock';held=os.open(path,os.O_RDWR|os.O_CREAT|os.O_EXCL,0o600)
                child=subprocess.Popen([sys.executable,'-c',
                    'import fcntl,time;fcntl.flock('+str(held)+',fcntl.LOCK_EX);print("ready",flush=True);time.sleep(20)'],
                    pass_fds=(held,),stdout=subprocess.PIPE)
                try:
                    self.assertTrue(select.select([child.stdout],[],[],3)[0]);self.assertEqual(child.stdout.readline(),b'ready\n')
                    os.close(held);held=None;real_open=os.pidfd_open;real_read=Path.read_text
                    def exited():
                        if child.poll()is None:child.terminate();child.wait(timeout=3)
                    def opened(pid,*args):
                        fd=real_open(pid,*args)
                        if when=='after_open':exited()
                        return fd
                    def read(leaf,*args,**kwargs):
                        if str(leaf)=='/proc/'+str(child.pid)+'/cgroup'and when=='during_proc':
                            exited();raise FileNotFoundError()
                        return real_read(leaf,*args,**kwargs)
                    library=SimpleNamespace(pidfd_getfd=mock.Mock(side_effect=AssertionError('dead actor cannot lend FD')))
                    facts={'MainPID':str(child.pid),'ControlPID':str(child.pid)}
                    with mock.patch.object(p,'LOCK',path),mock.patch.object(p,'_borrow_rotation_guard',return_value=None), \
                         mock.patch.object(p,'actor_module',return_value=actor), \
                         mock.patch.object(p,'state',return_value=(b'',{'manager':'systemd-networkd.service'})), \
                         mock.patch.object(p,'_actor_facts',return_value=facts),mock.patch.object(p.ctypes,'CDLL',return_value=library), \
                         mock.patch.object(p.os,'pidfd_open',side_effect=opened),mock.patch.object(Path,'read_text',read):
                        with p.guard_lock()as received:
                            self.assertIsNone(p._BORROW_CONTEXT)
                            self.assertEqual(os.fstat(received).st_ino,path.stat().st_ino)
                            other=os.open(path,os.O_RDONLY)
                            try:
                                with self.assertRaises(BlockingIOError):fcntl.flock(other,fcntl.LOCK_EX|fcntl.LOCK_NB)
                            finally:os.close(other)
                    library.pidfd_getfd.assert_not_called()
                finally:
                    if held is not None:os.close(held)
                    if child.poll()is None:child.terminate();child.wait(timeout=3)
                    child.stdout.close()

    @unittest.skipUnless(hasattr(__import__('os'),'pidfd_open'),'Linux PIDFD')
    def test_live_foreign_actor_identity_never_becomes_completed_actor_fallback(self):
        import os,subprocess,select,re
        from types import SimpleNamespace
        child=subprocess.Popen([sys.executable,'-c','import time;time.sleep(20)'])
        def alive(fd):
            poll=select.poll();poll.register(fd,select.POLLIN);return not poll.poll(0)
        actor=SimpleNamespace(Refused=RuntimeError,_alive=alive,
            _pidfd_pid=lambda fd:int(re.search(r'^Pid:\s*([0-9]+)',Path('/proc/self/fdinfo/'+str(fd)).read_text(),re.M)[1]))
        library=SimpleNamespace(pidfd_getfd=mock.Mock(side_effect=AssertionError('foreign actor cannot lend FD')))
        try:
            with mock.patch.object(p,'_borrow_rotation_guard',return_value=None),mock.patch.object(p,'actor_module',return_value=actor), \
                 mock.patch.object(p,'state',return_value=(b'',{'manager':'systemd-networkd.service'})), \
                 mock.patch.object(p,'_actor_facts',return_value={'MainPID':str(child.pid),'ControlPID':str(child.pid)}), \
                 mock.patch.object(p.ctypes,'CDLL',return_value=library):
                # The live child is in the test worker cgroup, not the claimed
                # source-pinned guardian unit. No actor exit can hide that.
                with self.assertRaisesRegex(p.ActorIdentityRefused,'OFD actor identity changed')as caught:p.borrow_actor_guard()
                self.assertEqual(p.refusal_coordinates(caught.exception)['identity_failure'],'cgroup')
                read=Path.read_text;stat=p.os.stat
                def known_cgroup(leaf,*args,**kw):
                    if str(leaf)=='/proc/'+str(child.pid)+'/cgroup':return '0::/system.slice/aegis-auto-guardian-watchdog.service\n'
                    return read(leaf,*args,**kw)
                def foreign_netns(leaf,*args,**kw):
                    if str(leaf)=='/proc/'+str(child.pid)+'/ns/net':return SimpleNamespace(st_ino=-1)
                    return stat(leaf,*args,**kw)
                with mock.patch.object(Path,'read_text',known_cgroup),mock.patch.object(p.os,'stat',foreign_netns):
                    with self.assertRaises(p.ActorIdentityRefused)as caught:p.borrow_actor_guard()
                row=p.refusal_coordinates(caught.exception)
                self.assertEqual((row['actor_kind'],row['identity_failure']),('watchdog','netns'))
            library.pidfd_getfd.assert_not_called();self.assertIsNone(child.poll())
        finally:child.terminate();child.wait(timeout=3)

    def test_sticky_drift_preserves_first_incident_on_restart(self):
        import json,tempfile
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'drift.json'
            with mock.patch.object(p,'DRIFT',path),mock.patch.object(Path,'read_text',return_value='fixture-boot'):
                p.publish_drift(True)
                before=path.read_bytes()
                with mock.patch.object(p,'trusted_read',side_effect=lambda x,*_:x.read_bytes()):
                    p.publish_drift(True)
                self.assertEqual(path.read_bytes(),before)
                self.assertEqual(json.loads(before)['reason'],'foreign_policy_drift')

    def test_missing_ufw_is_diagnostic_and_remains_a_refusal(self):
        with mock.patch.object(p,'run',return_value=b'{"nftables":[]}'):
            self.assertEqual(p.ufw_table_status(),'missing')
        with mock.patch.object(p,'run',side_effect=OSError('unavailable')):
            self.assertEqual(p.ufw_table_status(),'unknown')

    def test_disarmed_stop_does_not_reblock_or_wait_on_purge_lock(self):
        with mock.patch.object(p,'state',return_value=(b'',{'armed':'0'})),\
             mock.patch.object(p,'guard_lock',side_effect=AssertionError('purge deadlock')):
            p.revoke()

    def test_full_disk_cannot_prevent_block_and_client_stop(self):
        calls=[]
        def run(argv,**kwargs):
            calls.append(argv);return mock.Mock(returncode=0,stdout=b'')
        with mock.patch.object(p,'state',return_value=(b'',{'armed':'1'})), \
             mock.patch.object(p,'guard_lock',side_effect=lambda:contextlib.nullcontext(9)), \
             mock.patch.object(p,'publish_drift',side_effect=OSError(errno.ENOSPC,'full')), \
             mock.patch.object(p.subprocess,'run',side_effect=run):
            with self.assertRaises(ValueError):p.revoke()
        self.assertEqual(calls[0],['/bin/bash',p.HELPER,'block'])
        self.assertTrue(any(x[:3]==['systemctl','--no-block','stop'] for x in calls))

    def test_failed_block_still_requests_stopping_client(self):
        calls=[]
        def run(argv,**kwargs):
            calls.append(argv)
            if argv[0]=='/bin/bash':raise p.subprocess.TimeoutExpired(argv,40)
            return mock.Mock(returncode=0,stdout=b'')
        with mock.patch.object(p,'state',return_value=(b'',{'armed':'1'})), \
             mock.patch.object(p,'guard_lock',side_effect=lambda:contextlib.nullcontext(9)), \
             mock.patch.object(p,'publish_drift'), \
             mock.patch.object(p.subprocess,'run',side_effect=run):
            with self.assertRaises(ValueError):p.revoke()
        self.assertTrue(any(x==['systemctl','--no-block','stop','aegis-client.service'] for x in calls))

    def test_absent_auto_glob_is_not_a_failed_client_stop(self):
        calls=[]
        def run(argv,**kwargs):
            calls.append(argv)
            return mock.Mock(returncode=0,stdout=b'')
        with mock.patch.object(p.subprocess,'run',side_effect=run):
            self.assertTrue(p.stop_owned_units({'aegis-client.service',
                'aegis-auto@*.service','aegis-auto-config.service'}))
        self.assertEqual([argv for argv in calls if argv[:3] ==
                          ['systemctl','--no-block','stop']],
                         [['systemctl','--no-block','stop','aegis-client.service']])

    def test_failed_private_unit_bullet_still_gets_stopped(self):
        private='aegis-auto@' + 'a'*64 + '.service'
        calls=[]
        def run(argv,**kwargs):
            calls.append(argv)
            output=('● '+private+' loaded failed failed fixture\n').encode() \
                if argv[1]=='list-units' else b''
            return mock.Mock(returncode=0,stdout=output)
        with mock.patch.object(p.subprocess,'run',side_effect=run):
            self.assertTrue(p.stop_owned_units({'aegis-client.service',
                'aegis-auto@*.service','aegis-auto-config.service'}))
        self.assertIn(['systemctl','--no-block','stop',private],calls)

    def test_unavailable_unit_inventory_attempts_prior_fixed_stops(self):
        calls=[]
        def run(argv,**kwargs):
            calls.append(argv)
            return mock.Mock(returncode=1 if argv[1]=='list-units' else 0,
                             stdout=b'')
        with mock.patch.object(p.subprocess,'run',side_effect=run):
            self.assertFalse(p.stop_owned_units({'aegis-client.service',
                'aegis-auto@*.service','aegis-auto-config.service'}))
        for unit in ('aegis-client.service','aegis-auto@*.service',
                     'aegis-auto-config.service'):
            self.assertIn(['systemctl','--no-block','stop',unit],calls)

    def test_guard_lock_retains_context_manager_protocol(self):
        with mock.patch.object(p, 'LOCK', Path('/nonexistent-guard-lock')):
            context = p.guard_lock(reserve_assessment=True)
            self.assertTrue(hasattr(context, '__enter__'))
            self.assertTrue(hasattr(context, '__exit__'))

if __name__=='__main__':unittest.main()
