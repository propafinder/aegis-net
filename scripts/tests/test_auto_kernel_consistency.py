"""Disposable Linux/root stand: real RA, nft generation and PID1 timer bytes.

Opt in only on the disposable fleet guest. Network changes live in two new
namespaces; the host interfaces, firewall and management connection are unused.
The outer QA driver retains an independent guest snapshot inverse.
"""
import importlib.util
import fcntl
import hashlib
import json
import os
from pathlib import Path
import socket
import shlex
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import Mock, patch
from types import SimpleNamespace
import uuid

LIB=Path(__file__).resolve().parents[1]/'lib'
sys.path.insert(0,str(LIB))
import aegis_auto_foreign_monitor as monitor
import aegis_auto_foreign_policy as policy
spec=importlib.util.spec_from_file_location('stand_guardian',LIB/'aegis_auto_guardian.py')
guardian=importlib.util.module_from_spec(spec);spec.loader.exec_module(guardian)
spec=importlib.util.spec_from_file_location('stand_watchdog',LIB/'aegis_auto_guardian_watchdog.py')
watchdog=importlib.util.module_from_spec(spec);sys.modules[spec.name]=watchdog;spec.loader.exec_module(watchdog)


def run(*argv, input=None):
    result=subprocess.run(argv,input=input,capture_output=True,timeout=5)
    if result.returncode:
        raise AssertionError((argv,result.returncode,result.stderr.decode(errors='replace')))
    return result.stdout


@unittest.skipUnless(sys.platform=='linux' and os.geteuid()==0 and
                    os.environ.get('AEGIS_RUN_KERNEL_STAND')=='1', 'disposable Linux/root stand')
class KernelConsistency(unittest.TestCase):
    def test_stopped_guard_monitor_owner_actual_pid1_and_collected_private(self):
        """Positive admission uses real PID1, /proc, cgroup, pidfd and flock.

        Only the install receipt lookup is replaced with hashes of this
        disposable source and unit; no PID1/proc/lock observation is mocked.
        """
        unit='aegis-qa-stopped-monitor-'+uuid.uuid4().hex+'.service'
        fragment=Path('/etc/systemd/system')/unit
        with tempfile.TemporaryDirectory(prefix='aegis-qa-stopped-',dir='/var/lib') as folder:
            root=Path(folder)
            source=root/'monitor.py'
            guard=root/'device-guard.conf.lock'
            ready=root/'held'
            release=root/'release'
            guard.write_bytes(b'');guard.chmod(0o600)
            source.write_text(
                'import fcntl,os,pathlib,time\n'
                'guard='+repr(str(guard))+'\n'
                'ready=pathlib.Path('+repr(str(ready))+')\n'
                'release=pathlib.Path('+repr(str(release))+')\n'
                'fd=os.open(guard,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)\n'
                'fcntl.flock(fd,fcntl.LOCK_EX)\n'
                'ready.write_text("held")\n'
                'while not release.exists():time.sleep(.01)\n'
                'os.close(fd)\n')
            source.chmod(0o500)
            with fragment.open('x') as unit_file:unit_file.write('[Unit]\nDescription=Aegis disposable stopped guard owner\n'
                '[Service]\nType=exec\nSlice=system.slice\n'
                'RuntimeMaxSec=25s\nTimeoutStopSec=2s\n'
                'KillMode=control-group\n'
                'ExecStart=/usr/bin/python3 -I -B '+str(source)+'\n')
            fragment.chmod(0o644)
            try:
                run('systemctl','daemon-reload')
                run('systemctl','start','--no-block',unit)
                deadline=time.monotonic()+5
                while True:
                    state=dict(line.split('=',1)for line in run(
                        'systemctl','show',unit,'-pMainPID','-pActiveState',
                        '-pControlGroup','-pInvocationID').decode().splitlines())
                    if (ready.exists() and state['ActiveState']=='active' and
                            int(state['MainPID'])>1):break
                    self.assertLess(time.monotonic(),deadline,
                                    'PID1 never published held monitor owner')
                    time.sleep(.02)
                self.assertEqual(state['ControlGroup'],'/system.slice/'+unit)
                monitor_pid=int(state['MainPID'])
                install={'foreign_monitor_source_sha256':hashlib.sha256(source.read_bytes()).hexdigest(),
                         'foreign_monitor_unit_sha256':hashlib.sha256(fragment.read_bytes()).hexdigest()}
                identity=(guard.stat().st_dev,guard.stat().st_ino)
                with patch.object(guardian,'STOPPED_GUARD_UNIT',unit), \
                     patch.object(guardian,'FOREIGN_MONITOR_SOURCE',source), \
                     patch.object(guardian,'FOREIGN_UNIT_FILE',fragment), \
                     patch.object(guardian,'GUARD_LOCK',guard), \
                     patch.object(guardian,'record',return_value=install):
                    self.assertTrue(guardian._stopped_monitor_owner(
                        identity,time.monotonic()+2),
                        'exact live monitor must be admitted by actual kernel/PID1 proof')
                    contender=os.open(guard,os.O_RDONLY|os.O_NOFOLLOW)
                    try:
                        with self.assertRaises(BlockingIOError):
                            fcntl.flock(contender,fcntl.LOCK_EX|fcntl.LOCK_NB)
                    finally:os.close(contender)
                    # Real PID1 monitor releases after the first exact
                    # /proc/locks row, before the second PID1 read. The same
                    # guardian request must claim the original inode itself.
                    original_read=guardian._stopped_bounded_read
                    released=[]
                    def release_after_kernel_row(path, maximum):
                        data=original_read(path,maximum)
                        if str(path)=='/proc/locks' and not released:
                            released.append(True)
                            release.touch()
                            deadline=time.monotonic()+1
                            while True:
                                state=dict(line.split('=',1)for line in run(
                                    'systemctl','show',unit,'-pMainPID','-pActiveState')
                                    .decode().splitlines())
                                if state['MainPID']=='0' and state['ActiveState']!='active':
                                    break
                                self.assertLess(time.monotonic(),deadline,
                                    'disposable monitor did not release before continuity read')
                                time.sleep(.01)
                        return data
                    with patch.object(guardian,'_stopped_bounded_read',
                                      side_effect=release_after_kernel_row):
                        fd=guardian._stopped_guard_claim()
                    self.assertEqual(released,[True])
                    try:
                        self.assertEqual((os.fstat(fd).st_dev,os.fstat(fd).st_ino),identity)
                        contender=os.open(guard,os.O_RDONLY|os.O_NOFOLLOW)
                        try:
                            with self.assertRaises(BlockingIOError):
                                fcntl.flock(contender,fcntl.LOCK_EX|fcntl.LOCK_NB)
                        finally:os.close(contender)
                    finally:os.close(fd)
                private='aegis-auto@'+uuid.uuid4().hex*2+'.service'
                stopped=guardian._stopped_guard_pid1(private,'a'*32)
                self.assertEqual(stopped['MainPID'],'0')
                self.assertEqual(stopped['ActiveState'],'inactive')
                self.assertIn(stopped['LoadState'],('loaded','not-found'))
                print(json.dumps({'real_stopped_guard_monitor_owner':True,
                    'pid1_main':monitor_pid,
                    'original_guard_inode':list(identity),
                    'collected_private_pid1':True}))
            finally:
                release.touch()
                subprocess.run(['systemctl','stop',unit],capture_output=True,timeout=5)
                subprocess.run(['systemctl','reset-failed',unit],capture_output=True,timeout=5)
                fragment.unlink(missing_ok=True)
                subprocess.run(['systemctl','daemon-reload'],capture_output=True,timeout=5)

    def test_stopped_guard_borrowed_original_ofd_actual_pid1(self):
        """Real PID1 monitor retains a child's original FLOCK via SCM_RIGHTS.

        Install source hashes and paths are the only patched authority. PID1,
        pidfd, /proc/locks, /proc/PID/fdinfo and flock remain real kernel reads.
        """
        unit='aegis-qa-borrowed-monitor-'+uuid.uuid4().hex+'.service'
        fragment=Path('/etc/systemd/system')/unit
        with tempfile.TemporaryDirectory(prefix='aegis-qa-borrowed-',dir='/var/lib') as folder:
            root=Path(folder)
            source=root/'monitor.py'
            guard=root/'device-guard.conf.lock'
            ready=root/'held'
            release=root/'release'
            guard.write_bytes(b'');guard.chmod(0o600)
            source.write_text(
                'import array,fcntl,os,pathlib,socket,time\n'
                'guard='+repr(str(guard))+'\n'
                'ready=pathlib.Path('+repr(str(ready))+')\n'
                'release=pathlib.Path('+repr(str(release))+')\n'
                'parent,child=socket.socketpair(socket.AF_UNIX,socket.SOCK_SEQPACKET)\n'
                'locker=os.fork()\n'
                'if locker==0:\n'
                '    parent.close()\n'
                '    fd=os.open(guard,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)\n'
                '    fcntl.flock(fd,fcntl.LOCK_EX)\n'
                '    child.sendmsg([b"LOCKED"],[(socket.SOL_SOCKET,socket.SCM_RIGHTS,array.array("i",[fd]))])\n'
                '    os.close(fd);child.close();os._exit(0)\n'
                'child.close()\n'
                'message,controls,_,_=parent.recvmsg(32,socket.CMSG_SPACE(array.array("i").itemsize))\n'
                'if message!=b"LOCKED":raise RuntimeError("missing original locker")\n'
                'fds=array.array("i")\n'
                'for level,kind,data in controls:\n'
                '    if level==socket.SOL_SOCKET and kind==socket.SCM_RIGHTS:\n'
                '        fds.frombytes(data[:fds.itemsize])\n'
                'if len(fds)!=1:raise RuntimeError("missing borrowed OFD")\n'
                'borrowed=fds[0]\n'
                'parent.close()\n'
                '_,status=os.waitpid(locker,0)\n'
                'if not os.WIFEXITED(status) or os.WEXITSTATUS(status)!=0:\n'
                '    raise RuntimeError("original locker failed")\n'
                'ready.write_text(str(locker))\n'
                'while not release.exists():time.sleep(.01)\n'
                'os.close(borrowed)\n')
            source.chmod(0o500)
            with fragment.open('x') as unit_file:unit_file.write(
                '[Unit]\nDescription=Aegis disposable borrowed stopped guard owner\n'
                '[Service]\nType=exec\nSlice=system.slice\n'
                'RuntimeMaxSec=25s\nTimeoutStopSec=2s\n'
                'KillMode=control-group\n'
                'ExecStart=/usr/bin/python3 -I -B '+str(source)+'\n')
            fragment.chmod(0o644)
            try:
                run('systemctl','daemon-reload')
                run('systemctl','start','--no-block',unit)
                deadline=time.monotonic()+5
                while True:
                    state=dict(line.split('=',1)for line in run(
                        'systemctl','show',unit,'-pMainPID','-pActiveState',
                        '-pControlGroup','-pInvocationID').decode().splitlines())
                    if (ready.exists() and state['ActiveState']=='active' and
                            int(state['MainPID'])>1):break
                    self.assertLess(time.monotonic(),deadline,
                                    'PID1 never published borrowed monitor owner')
                    time.sleep(.02)
                monitor_pid=int(state['MainPID'])
                locker_pid=int(ready.read_text())
                self.assertNotEqual(locker_pid,monitor_pid)
                self.assertEqual(state['ControlGroup'],'/system.slice/'+unit)
                identity=(guard.stat().st_dev,guard.stat().st_ino)
                rows=[]
                for line in Path('/proc/locks').read_text().splitlines():
                    row=line.split()
                    if len(row)!=8 or row[1:4]!=['FLOCK','ADVISORY','WRITE']:
                        continue
                    parts=row[5].split(':')
                    if len(parts)!=3:continue
                    try:
                        observed=(os.makedev(int(parts[0],16),int(parts[1],16)),
                                  int(parts[2]))
                    except ValueError:continue
                    if observed==identity:rows.append(row)
                self.assertEqual(len(rows),1)
                self.assertEqual(rows[0][6:],['0','EOF'])
                self.assertNotEqual(rows[0][4],str(monitor_pid),
                                    'kernel must expose the borrowed-owner case')
                install={'foreign_monitor_source_sha256':hashlib.sha256(source.read_bytes()).hexdigest(),
                         'foreign_monitor_unit_sha256':hashlib.sha256(fragment.read_bytes()).hexdigest()}
                with patch.object(guardian,'STOPPED_GUARD_UNIT',unit), \
                     patch.object(guardian,'FOREIGN_MONITOR_SOURCE',source), \
                     patch.object(guardian,'FOREIGN_UNIT_FILE',fragment), \
                     patch.object(guardian,'GUARD_LOCK',guard), \
                     patch.object(guardian,'record',return_value=install):
                    self.assertTrue(guardian._stopped_monitor_owner(
                        identity,time.monotonic()+2),
                        'borrowed original OFD must be authenticated by actual PID1/proc/fdinfo')
                    contender=os.open(guard,os.O_RDONLY|os.O_NOFOLLOW)
                    try:
                        with self.assertRaises(BlockingIOError):
                            fcntl.flock(contender,fcntl.LOCK_EX|fcntl.LOCK_NB)
                    finally:os.close(contender)
                    release.touch()
                    deadline=time.monotonic()+2
                    while True:
                        current=dict(line.split('=',1)for line in run(
                            'systemctl','show',unit,'-pMainPID','-pActiveState')
                            .decode().splitlines())
                        if current['MainPID']=='0' and current['ActiveState']!='active':break
                        self.assertLess(time.monotonic(),deadline,
                                        'borrowed monitor did not exit after release')
                        time.sleep(.01)
                    fd=guardian._stopped_guard_claim()
                    try:
                        self.assertEqual((os.fstat(fd).st_dev,os.fstat(fd).st_ino),identity)
                    finally:os.close(fd)
                print(json.dumps({'real_borrowed_stopped_guard_monitor_owner':True,
                                  'original_row_pid_differs_from_main':True,
                                  'contender_refused_until_release':True,
                                  'claim_after_release':True}))
            finally:
                release.touch()
                subprocess.run(['systemctl','stop',unit],capture_output=True,timeout=5)
                subprocess.run(['systemctl','reset-failed',unit],capture_output=True,timeout=5)
                fragment.unlink(missing_ok=True)
                subprocess.run(['systemctl','daemon-reload'],capture_output=True,timeout=5)

    def test_shell_identity_reads_real_control_then_main(self):
        import re
        unit='aegis-qa-identity-'+uuid.uuid4().hex+'.service'
        source=(LIB.parent/'aegis-device-egress-guard.sh').read_text()
        functions='\n'.join(re.search(r'^'+name+r'\(\) \{\n.*?^\}',source,re.M|re.S)[0]
                            for name in ('read_unit_identity','resolve_unit_cgroup'))
        with tempfile.TemporaryDirectory(prefix='aegis-qa-identity-',dir='/var/lib')as folder:
            root=Path(folder);gate=root/'release';result=root/'identity'
            program='set -eu\numask 077\n'+functions+'\n'
            program+='resolve_unit_cgroup '+shlex.quote(unit)+' 1\n'
            program+='printf "%s\\n%s\\n%s\\n%s\\n" "$resolved_path" "$resolved_inode" "$resolved_invocation" "$unit_control_pid" > identity\n'
            program+='while [[ ! -e release ]]; do sleep .02; done\n'
            (root/'prestart.sh').write_text(program)
            try:
                run('systemd-run','--no-block','--unit='+unit,'--property=Type=exec',
                    '--property=Slice=system.slice','--property=WorkingDirectory='+folder,
                    '--property=ExecStartPre=/bin/bash prestart.sh',
                    '--property=RuntimeMaxSec=25s','--property=TimeoutStartSec=8s',
                    '/usr/bin/sleep','20')
                end=time.monotonic()+4
                while not result.exists() or len(result.read_text().splitlines())!=4 or not result.read_text().endswith('\n'):
                    self.assertLess(time.monotonic(),end);time.sleep(.02)
                path,inode,invocation,control=result.read_text().splitlines()
                facts=dict(line.split('=',1)for line in run('systemctl','show',unit,
                    '-pMainPID','-pControlPID','-pInvocationID','-pControlGroup','-pSubState').decode().splitlines())
                self.assertEqual(facts['MainPID'],'0');self.assertEqual(facts['SubState'],'start-pre')
                self.assertEqual(control,facts['ControlPID']);self.assertGreater(int(control),1)
                self.assertEqual('/'+path,facts['ControlGroup'])
                self.assertEqual(invocation,facts['InvocationID'])
                self.assertEqual(int(inode),Path('/sys/fs/cgroup',path).stat().st_ino)
                gate.touch();end=time.monotonic()+4
                while True:
                    live=dict(line.split('=',1)for line in run('systemctl','show',unit,
                        '-pMainPID','-pActiveState').decode().splitlines())
                    if live['ActiveState']=='active' and int(live['MainPID'])>1:break
                    self.assertLess(time.monotonic(),end);time.sleep(.02)
                # A fresh non-caller receipt lookup must see this same invocation
                # after ControlPID goes away and Main is published.
                check='set -eu\n'+functions+'\nresolve_unit_cgroup '+shlex.quote(unit)+' 0\n'
                check+='[[ "$resolved_invocation" == '+shlex.quote(invocation)+' && "$unit_control_pid" == 0 ]]\n'
                run('/bin/bash','-c',check)
                print(json.dumps({'real_shell_control_identity':True,'main_zero_prestart':True,
                                  'fresh_main_identity':True,'original_checkpoints_retained':True}))
            finally:
                gate.touch();run('systemctl','stop',unit)

    def test_verified_membership_brackets_real_execstartpre_then_main(self):
        unit='aegis-auto@'+uuid.uuid4().hex*2+'.service'
        with tempfile.TemporaryDirectory(prefix='aegis-qa-prestart-',dir='/var/lib')as folder:
            root=Path(folder);gate=root/'release'
            (root/'prestart.py').write_text('import pathlib,time\nwhile not pathlib.Path("release").exists():time.sleep(.02)\n')
            try:
                run('systemd-run','--no-block','--unit='+unit,'--property=Type=exec',
                    '--property=Slice=system.slice','--property=WorkingDirectory='+folder,
                    '--property=ExecStartPre=/usr/bin/python3 prestart.py',
                    '--property=RuntimeMaxSec=25s','--property=TimeoutStartSec=8s',
                    '/usr/bin/python3','-c','import time;time.sleep(20)')
                def facts():
                    return dict(x.split('=',1)for x in run('systemctl','show',unit,
                        '-pMainPID','-pControlPID','-pInvocationID','-pControlGroup',
                        '-pActiveState','-pSubState').decode().splitlines())
                end=time.monotonic()+4
                while True:
                    first=facts()
                    if first['SubState']=='start-pre'and int(first['ControlPID'])>1:break
                    self.assertLess(time.monotonic(),end);time.sleep(.02)
                self.assertEqual(first['MainPID'],'0')
                binding={'path':'system.slice/'+unit,'invocation':first['InvocationID']}
                context={'private_unit':unit,'private_main_pid':None,'verified_client_binding':binding}
                with patch.object(monitor,'_BORROW_CONTEXT',context):
                    monitor.cgroup_members()
                    binding['invocation']='0'*32
                    with self.assertRaises(monitor.CgroupTransition):monitor.cgroup_members()
                    binding['invocation']=first['InvocationID'];gate.touch();end=time.monotonic()+4
                    while True:
                        active=facts()
                        if active['ActiveState']=='active'and int(active['MainPID'])>1:break
                        self.assertLess(time.monotonic(),end);time.sleep(.02)
                    monitor.cgroup_members()
                print(json.dumps({'real_execstartpre_main_zero':True,'original_control_bracketed':True,
                    'foreign_invocation_refused':True,'fresh_main_publication_verified':True}))
            finally:
                gate.touch();run('systemctl','stop',unit)

    def test_pending_stop_authenticates_actual_pid1_execstop_process(self):
        unit='aegis-auto@'+uuid.uuid4().hex*2+'.service'
        with tempfile.TemporaryDirectory(prefix='aegis-qa-stop-',dir='/var/lib')as folder:
            root=Path(folder);gate=root/'release'
            (root/'auto-stop-service').write_text(
                'import pathlib,time\n'
                'while not pathlib.Path("release").exists():time.sleep(.02)\n')
            try:
                run('systemd-run','--unit='+unit,'--property=Type=exec',
                    '--property=Slice=system.slice',
                    '--property=WorkingDirectory='+folder,
                    '--property=ExecStop=/usr/bin/python3 auto-stop-service '+unit,
                    '--property=RuntimeMaxSec=30s','--property=TimeoutStopSec=8s',
                    '/usr/bin/python3','-c','import time;time.sleep(25)')
                def facts():
                    return dict(x.split('=',1)for x in run('systemctl','show',unit,
                        '-pMainPID','-pControlPID','-pInvocationID','-pControlGroup',
                        '-pActiveState','-pSubState').decode().splitlines())
                active=facts();self.assertEqual(active['ActiveState'],'active')
                self.assertEqual(active['ControlGroup'],'/system.slice/'+unit)
                held=Mock(identity=SimpleNamespace(unit=unit,pid=int(active['MainPID']),
                    invocation=active['InvocationID'],cgroup=active['ControlGroup']))
                pin=guardian.executable_digest(Path('/usr/bin/python3'))
                run('systemctl','stop','--no-block',unit)
                until=time.monotonic()+4;proven=False
                while time.monotonic()<until:
                    current=facts()
                    if current['ControlPID']!='0'and current['SubState']=='stop':
                        try:proven=guardian._pending_owned_stop(unit,held,pin)
                        except (OSError,guardian.Refused):pass  # fork/exec publication
                        if proven:break
                    time.sleep(.01)
                self.assertTrue(proven,'actual typed ExecStop must be authenticated')
                with self.assertRaises(guardian.Refused):
                    guardian._pending_owned_stop(unit,held,'0'*64)
                self.assertEqual(facts()['InvocationID'],active['InvocationID'])
            finally:
                gate.touch()
                subprocess.run(['systemctl','stop',unit],capture_output=True,timeout=10)
                subprocess.run(['systemctl','reset-failed',unit],capture_output=True,timeout=5)

    def test_fresh_watchdog_recovery_retains_ofd_and_kills_its_whole_leaf(self):
        unit='aegis-auto-guardian-watchdog.service'
        value=run('systemctl','show',unit,'--value','-pLoadState').strip()
        self.assertEqual(value,b'not-found','fresh stand requires no installed watchdog generation')
        with tempfile.TemporaryDirectory(prefix='aegis-qa-watchdog-',dir='/var/lib') as folder:
            try:
                result=subprocess.run(['systemd-run','--wait','--pipe','--collect','--unit='+unit,
                    '--property=Delegate=yes','--property=RuntimeMaxSec=20s',
                    '--property=TimeoutStopSec=2s','--property=KillMode=control-group',
                    '/usr/bin/python3','-I','-B',str(Path(__file__).resolve()),
                    '--watchdog-stand',folder],capture_output=True,timeout=25)
                self.assertEqual(result.returncode,0,result.stderr.decode(errors='replace'))
                self.assertEqual(json.loads((Path(folder)/'result.json').read_text()),
                                 {'original_ofd_retained':True,'whole_leaf_dead':True})
            finally:
                subprocess.run(['systemctl','stop',unit],capture_output=True,timeout=5)
                subprocess.run(['systemctl','reset-failed',unit],capture_output=True,timeout=5)

    def test_real_getgen_has_stable_identity_and_accepts_queued_reply(self):
        with socket.socket(socket.AF_NETLINK,socket.SOCK_RAW|socket.SOCK_NONBLOCK,12) as peer:
            peer.bind((0,0))
            first=monitor.get_generation(peer)
            self.assertIs(type(first),int)
            self.assertEqual(first,monitor.get_generation(peer))
            class Delayed:
                def send(self,raw):peer.send(raw)
                def recv(self,size):return peer.recv(size)
                def fileno(self):time.sleep(.15);return peer.fileno()
            self.assertEqual(first,monitor.get_generation(Delayed()))

    def test_fresh_stable_retry_may_finish_after_poll_interval_without_using_old_proof(self):
        # Only scheduling is isolated here; policy/cgroup admission controls
        # remain in the separate full source and installed cohorts. Both
        # generation brackets below use the actual private kernel namespace.
        code="""import contextlib,json,socket,subprocess,sys,time
from unittest.mock import patch
sys.path.insert(0,sys.argv[1]);import aegis_auto_foreign_monitor as m
calls=0
def snapshot(*args,**kwargs):
 global calls
 calls+=1
 raw=subprocess.check_output(['nft','-j','list','tables'],timeout=3)
 if calls==1:
  time.sleep(1.1)
  subprocess.run(['nft','add','table','inet','aegis_qa_transition'],check=True,timeout=3)
 else:time.sleep(1.1)
 return {'call':calls,'tables':json.loads(raw)}
with socket.socket(socket.AF_NETLINK,socket.SOCK_RAW|socket.SOCK_NONBLOCK,12)as peer:
 peer.bind((0,0));began=time.monotonic()
 with patch.object(m,'guard_lock',side_effect=lambda **_kwargs:contextlib.nullcontext()),patch.object(m,'state',return_value=(b'',{'armed':'1','uplink':'lo'})),patch.object(m,'assessment_options',return_value={}),patch.object(m,'assess_foreign_policy',side_effect=snapshot),patch.object(m,'cgroup_members'):
  proof=m.stable_assessment(peer)
 assert calls==2 and proof['call']==2 and 'aegis_qa_transition' in json.dumps(proof['tables'])
 assert time.monotonic()-began>1
print(json.dumps({'fresh_complete_snapshot':True,'passes':calls,'seconds':time.monotonic()-began}))
"""
        value=json.loads(run('unshare','--net','/usr/bin/python3','-I','-B','-c',code,str(LIB)))
        self.assertTrue(value['fresh_complete_snapshot']);self.assertEqual(value['passes'],2)

    def test_real_local_nft_render_roundtrip_for_both_modes(self):
        # Real PID1 cgroups; all nft objects live only in a new network namespace.
        unit='aegis-auto@'+uuid.uuid4().hex*2+'.service'
        try:
            run('systemd-run','--unit='+unit,'--property=Slice=system.slice','--property=RuntimeMaxSec=60s',
                '--property=TimeoutStopSec=2s','--property=NoNewPrivileges=yes',
                '--property=CapabilityBoundingSet=','/usr/bin/sleep','50')
            group=Path('/sys/fs/cgroup/system.slice')/unit
            until=time.monotonic()+3
            while not group.exists() and time.monotonic()<until:time.sleep(.02)
            self.assertTrue(group.is_dir())
            data={'unit':unit,'inode':group.stat().st_ino,
                  'manager_inode':Path('/sys/fs/cgroup/system.slice/systemd-networkd.service').stat().st_ino}
            program=r"""import pathlib,json,subprocess,sys,hashlib
sys.path.insert(0,sys.argv[1]);import aegis_auto_guard_policy as p
D=json.loads(sys.argv[2]);rows=[]
subprocess.run(['ip','link','set','lo','up'],check=True)
subprocess.run(['ip','link','add','eth0','type','dummy'],check=True)
subprocess.run(['ip','addr','add','198.51.100.2/24','dev','eth0'],check=True)
subprocess.run(['ip','link','set','eth0','up'],check=True)
subprocess.run(['ip','route','add','default','dev','eth0'],check=True)
for profile in('output_only_safe','full_wide_tun'):
 binding={'stage_dev':1,'stage_ino':2,'private_unit':D['unit'],
  'transaction_nonce':'a'*32,'planned_generation':'b'*64,
  'boot_id':pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
  'netns_ino':pathlib.Path('/proc/self/ns/net').stat().st_ino,
  'config_sha256_initial':'c'*64,'config_semantic_sha256':'d'*64,
  'listen_ipv4':'127.0.0.1','listen_port':980 if profile=='full_wide_tun'else 15080,
  'dns_port':53,'udp_port':1980 if profile=='full_wide_tun'else None,
  'profile':profile,'first_arm_sha256':'e'*64 if profile=='full_wide_tun'else None,
  'guard_policy_sha256':'f'*64,'guard_state_sha256':'1'*64,
  'uplink':'eth0','management_ports':[22],'dhcp4':True,
  'manager_binding':{'schema':'aegis_device_guard_binding_v1',
    'boot_id':pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
    'state_sha256':'1'*64,'path':'system.slice/systemd-networkd.service',
    'inode':str(D['manager_inode']),'invocation':'2'*32}}
 bound={'cgroup_path':'system.slice/'+D['unit'],'cgroup_inode':D['inode']}
 script=p._local_script(binding,bound)
 q=subprocess.run(['/usr/sbin/nft','-f','-'],input=script,capture_output=True,timeout=3)
 row={'profile':profile,'render_rc':q.returncode,'script_sha256':hashlib.sha256(script).hexdigest()}
 if q.returncode==0:
  raw=subprocess.check_output(['/usr/sbin/nft','-j','-a','list','table','ip',p.LOCAL_TABLE],timeout=3)
  row.update(actual=json.loads(raw),expected=p._local_expected(binding,bound),
   text=subprocess.check_output(['/usr/sbin/nft','-a','list','table','ip',p.LOCAL_TABLE],timeout=3).decode())
  try:row['projection']=p._local_projection(binding,bound);row['verified']=True
  except p.PolicyRefused:row['verified']=False
  if row['verified']:
   import socket,threading,time
   ports=(('tcp',binding['listen_port']),('udp',53))
   if profile=='full_wide_tun':ports+=(('udp',binding['udp_port']),)
   stop=threading.Event();listeners=[];threads=[]
   def echo(sock,protocol):
    while not stop.is_set():
     try:
      if protocol=='tcp':
       peer,_=sock.accept();peer.settimeout(.5)
       try:peer.sendall(peer.recv(64))
       except OSError:pass
       finally:peer.close()
      else:
       payload,peer=sock.recvfrom(64);sock.sendto(payload,peer)
     except socket.timeout:pass
     except OSError:break
   try:
    for protocol,port in ports:
     sock=socket.socket(socket.AF_INET,socket.SOCK_STREAM if protocol=='tcp'else socket.SOCK_DGRAM)
     sock.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);sock.bind(('127.0.0.1',port));sock.settimeout(.1)
     if protocol=='tcp':sock.listen(8)
     listeners.append(sock);thread=threading.Thread(target=echo,args=(sock,protocol),daemon=True);thread.start();threads.append(thread)
    state={'uplink':'eth0','capture_profile':'wide-redirect-safe' if profile=='output_only_safe'else 'full-wide-tun',
      'management_ports':'22','dhcp4':'0','dhcp6':'0'}
    client={'path':bound['cgroup_path'],'boot_id':binding['boot_id'],'state_sha256':'1'*64,
      'inode':str(bound['cgroup_inode']),'invocation':'2'*32}
    extra=(('udp',53),)+( (('tcp',980),('udp',binding['udp_port'])) if profile=='full_wide_tun'else ())
    def install(extra):
     # Execute the actual shell renderer with explicit fixture port inputs.
     # Protected-intent admission has separate owner/state/cgroup negatives.
     # nft 1.1.6 cannot ingest its own socket-cgroup JSON spelling, so use
     # production text input, not a second renderer or a JSON approximation.
     import shlex
     source=(pathlib.Path(sys.argv[1]).parent/'aegis-device-egress-guard.sh').read_text()
     body='render() {'+source.split('\nrender() {',1)[1].split('\n}\n\nselected_relay_script=',1)[0]+'\n}\n'
     body=body.replace("local local_dnat_ports='' protocol",'local local_dnat_ports='+shlex.quote('\n'.join(protocol+' '+str(port)for protocol,port in extra))+' protocol',1)
     env={'PATH':'/usr/sbin:/usr/bin:/bin','LANG':'C','schema':'aegis_device_guard_v2',
       'TABLE':p.TABLE,'capture_profile':state['capture_profile'],'capture_interface':'aegis-tun0',
       'uplink':'eth0','management_ports':'22','dhcp4':'0','dhcp6':'0','client_path':'',
       'client_unit':'','client_inode':client['inode'],'client_invocation':client['invocation']}
     marker=p._marker(client,'client')
     command='set -eu\nbinding_marker() { printf "%s\\n" '+shlex.quote(marker)+'; }\n'+body+'\nrender "$1"\n'
     generated=subprocess.run(['/bin/bash','--noprofile','--norc','-c',command,'stand',bound['cgroup_path']],env=env,capture_output=True,timeout=3)
     assert generated.returncode==0,generated.stderr.decode()
     q=subprocess.run(['/usr/sbin/nft','-f','-'],input=generated.stdout,capture_output=True,timeout=3)
     assert q.returncode==0,q.stderr.decode()
     actual=subprocess.check_output(['/usr/sbin/nft','-j','-a','list','table','inet',p.TABLE],timeout=3)
     projection=p.policy_projection(actual)[0]
     parsed,_=p._canonical_rules(projection)
     expected=p._expected(state,client,None,local_dnat_ports=extra)
     assert parsed==p._expected_with_elided_levels(expected,parsed)
    def exchange(protocol,port,target,timeout):
     with socket.socket(socket.AF_INET,socket.SOCK_STREAM if protocol=='tcp'else socket.SOCK_DGRAM)as sock:
      sock.settimeout(timeout);nonce=os.urandom(32)
      try:
       sock.connect((target,53 if port==53 else 18080));sock.send(nonce);return sock.recv(64)==nonce
      except (OSError,socket.timeout):return False
    import os
    install(())
    # The old renderer drops TCP980 and both DNS53 paths before NAT reroute.
    old_protocol,old_port=('tcp',980)if profile=='full_wide_tun'else ('udp',53)
    row['old_guard_dropped_capture']=not exchange(old_protocol,old_port,'192.0.2.251',.15)
    subprocess.run(['/usr/sbin/nft','delete','table','inet',p.TABLE],check=True,capture_output=True,timeout=3)
    install(extra)
    row['loopback_dnat_echoes']=[exchange(protocol,port,'192.0.2.251',.8)for protocol,port in ports]
    # Remove only this namespace's local capture table: the same external
    # destination must still be denied by the new guard, not accepted on WAN.
    subprocess.run(['/usr/sbin/nft','delete','table','ip',p.LOCAL_TABLE],check=True,capture_output=True,timeout=3)
    row['wan_still_denied']=not exchange('tcp',980,'192.0.2.251',.15)
    subprocess.run(['/usr/sbin/nft','delete','table','inet',p.TABLE],check=True,capture_output=True,timeout=3)
    subprocess.run(['/usr/sbin/nft','-f','-'],input=script,check=True,capture_output=True,timeout=3)
   finally:
    stop.set()
    for sock in listeners:sock.close()
    for thread in threads:thread.join(.3)
   for name,bad in (

    ('foreign_cgroup',p._local_script(binding,dict(bound,cgroup_path='system.slice/systemd-networkd.service',cgroup_inode=D['manager_inode']))),
    ('wrong_level',script.replace(('level 2 "'+bound['cgroup_path']+'"').encode(),('level 1 "'+bound['cgroup_path']+'"').encode(),1)),
    ('extra_rule',script+b'add rule ip aegis_auto_local_redirect output counter accept\n')):
    subprocess.run(['/usr/sbin/nft','delete','table','ip',p.LOCAL_TABLE],check=True,capture_output=True,timeout=3)
    q=subprocess.run(['/usr/sbin/nft','-f','-'],input=bad,capture_output=True,timeout=3)
    row[name+'_render_rc']=q.returncode
    if q.returncode:row[name+'_refused']=True
    else:
     try:p._local_projection(binding,bound);row[name+'_refused']=False
     except p.PolicyRefused:row[name+'_refused']=True
  subprocess.run(['/usr/sbin/nft','delete','table','ip',p.LOCAL_TABLE],check=True,capture_output=True,timeout=3)
 rows.append(row)
# A stopped cgroup may no longer have a path; its pinned numeric rule must
# remain verifiable for the restrictive retirement path.
q=subprocess.run(['/usr/sbin/nft','-f','-'],input=script,capture_output=True,timeout=3)
assert q.returncode==0
subprocess.run(['systemctl','stop',D['unit']],check=True,capture_output=True,timeout=5)
import time
end=time.monotonic()+3;group=pathlib.Path('/sys/fs/cgroup')/bound['cgroup_path']
while group.exists()and time.monotonic()<end:time.sleep(.02)
retired={'cgroup_gone':not group.exists()}
try:p._local_projection(binding,bound);retired['verified']=True
except (p.PolicyRefused,OSError):retired['verified']=False
retired['actual']=json.loads(subprocess.check_output(['/usr/sbin/nft','-j','-a','list','table','ip',p.LOCAL_TABLE],timeout=3))
print(json.dumps({'local_nft_shape':rows,'stopped_cgroup':retired}))
"""
            value=json.loads(run('unshare','--net','/usr/bin/python3','-I','-B','-c',program,str(LIB),json.dumps(data)))
            print(json.dumps(value),flush=True)
            self.assertTrue(value['stopped_cgroup']['cgroup_gone'])
            self.assertTrue(value['stopped_cgroup']['verified'])
            self.assertTrue(all(row['old_guard_dropped_capture'] and all(row['loopback_dnat_echoes']) and row['wan_still_denied'] for row in value['local_nft_shape']))
            self.assertTrue(all(row.get('verified') and all(row.get(name+'_refused') for name in
                ('foreign_cgroup','wrong_level','extra_rule')) for row in value['local_nft_shape']))
        finally:
            subprocess.run(['systemctl','stop',unit],capture_output=True,timeout=5)

    def test_real_owned_tun_delete_and_residual_table_require_exact_deny(self):
        unit='aegis-auto@'+uuid.uuid4().hex*2+'.service'
        try:
            run('systemd-run','--unit='+unit,'--property=Slice=system.slice',
                '--property=RuntimeMaxSec=40s','/usr/bin/sleep','35')
            group=Path('/sys/fs/cgroup/system.slice')/unit
            self.assertTrue(group.is_dir())
            data={'unit':unit,'inode':group.stat().st_ino}
            program=r"""import contextlib,fcntl,hashlib,json,pathlib,shlex,socket,subprocess,sys,tempfile
from types import SimpleNamespace
from unittest.mock import patch
# Keep installed-source ancestry checks real: /var/tmp is intentionally
# writable, so stage these four exact source files in private /var/lib.
trusted=tempfile.TemporaryDirectory(prefix='aegis-qa-stop-source-',dir='/var/lib')
lib=pathlib.Path(trusted.name)
for name in ('aegis_auto_guard_policy.py','aegis_auto_foreign_policy.py','aegis_auto_foreign_monitor.py','aegis_auto_native_witness.py'):
 raw_source=(pathlib.Path(sys.argv[1])/name).read_bytes();(lib/name).write_bytes(raw_source);(lib/name).chmod(0o644)
 assert hashlib.sha256((lib/name).read_bytes()).digest()==hashlib.sha256(raw_source).digest()
sys.path.insert(0,str(lib));import aegis_auto_guard_policy as p
import aegis_auto_foreign_policy as f
import aegis_auto_foreign_monitor as m
D=json.loads(sys.argv[2]);boot=pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip()
def cmd(*args,input=None):return subprocess.run(args,input=input,capture_output=True,check=True,timeout=3).stdout
cmd('ip','link','set','lo','up');cmd('ip','link','add','eth0','type','dummy')
cmd('ip','link','set','eth0','up');cmd('ip','route','add','default','dev','eth0')
cmd('ip','tuntap','add','dev','aegis-tun0','mode','tun')
raw=b'schema=aegis_device_guard_v2\narmed=1\nservice=aegis-client.service\nuplink=eth0\nmanager=systemd-networkd.service\ncapture_interface=aegis-tun0\nmanagement_address_policy=current_local\nmanagement_ports=22\ndhcp4=0\ndhcp6=0\ninitramfs_network=absent_verified\n'
source=(pathlib.Path(sys.argv[1]).parent/'aegis-device-egress-guard.sh').read_text()
body='render() {'+source.split('\nrender() {',1)[1].split('\n}\n\nselected_relay_script=',1)[0]+'\n}\n'
env={'PATH':'/usr/sbin:/usr/bin:/bin','LANG':'C','schema':'aegis_device_guard_v2',
 'TABLE':p.TABLE,'capture_profile':'full-wide-tun','capture_interface':'aegis-tun0',
 'uplink':'eth0','management_ports':'22','dhcp4':'0','dhcp6':'0','client_path':'','client_unit':''}
script=subprocess.run(['/bin/bash','--noprofile','--norc','-c','set -eu\n'+body+'\nrender ""\n'],env=env,capture_output=True,check=True,timeout=3).stdout
cmd('nft','-f','-',input=script)
with tempfile.TemporaryDirectory(prefix='aegis-qa-stop-',dir='/var/lib') as folder:
 root=pathlib.Path(folder);p.SCOPED_PARENT=root
 p.LOCAL_INTENT=root/'local-intent.json';p.LOCAL_BOUND=root/'local-bound.json';p.LOCAL_ACTIVE=root/'local-active.json'
 state=root/'device-guard.conf';state.write_bytes(raw);state.chmod(0o600)
 intent={'schema':'aegis_auto_stop_intent_v1','boot_id':boot,'service':D['unit'],'invocation_id':'a'*32,'phase':'pending_deny'}
 p._scoped_write(root/'auto-stop-intent.json',intent)
 binding={'stage_dev':1,'stage_ino':2,'private_unit':D['unit'],'transaction_nonce':'a'*32,
  'planned_generation':'b'*64,'boot_id':boot,'netns_ino':pathlib.Path('/proc/self/ns/net').stat().st_ino,
  'config_sha256_initial':'c'*64,'config_semantic_sha256':'d'*64,'listen_ipv4':'127.0.0.1',
  'listen_port':980,'dns_port':53,'udp_port':981,'profile':'full_wide_tun','first_arm_sha256':'e'*64,
  'guard_policy_sha256':'f'*64,'guard_state_sha256':hashlib.sha256(raw.rstrip(b'\n')).hexdigest(),
  'uplink':'eth0','management_ports':[22],'dhcp4':False,'manager_binding':None}
 local_intent=p._local_intent(binding);p._scoped_write(p.LOCAL_INTENT,local_intent)
 bound={'schema':'aegis_auto_local_redirect_bound_v1','intent_sha256':p._scoped_hash(local_intent),
  'invocation_id':'a'*32,'cgroup_path':'system.slice/'+D['unit'],'cgroup_inode':D['inode']}
 p._scoped_write(p.LOCAL_BOUND,bound);cmd('nft','-f','-',input=p._local_script(binding,bound))
 p._scoped_write(p.LOCAL_ACTIVE,{'schema':'aegis_auto_local_redirect_active_v1','bound_sha256':p._scoped_hash(bound),'policy':p._local_projection(binding,bound)})
 first=f.normalize(json.loads(cmd('nft','--json','list','ruleset')))
 cmd('systemctl','stop',D['unit']);assert not (pathlib.Path('/sys/fs/cgroup')/bound['cgroup_path']).exists()
 second=f.normalize(json.loads(cmd('nft','--json','list','ruleset')))
 # Some nft/kernel combinations display the numeric inode even while the
 # cgroup exists. Record that platform as unsupported for this transition;
 # never turn an unrelated difference into an accepted assessment.
 def is_local(row):
  obj=next(iter(row.values()))
  return obj.get('family')=='ip' and obj.get('table',obj.get('name'))==p.LOCAL_TABLE
 def local_rows(snapshot):return [row for row in snapshot['nftables'] if is_local(row)]
 def without_local(snapshot):
  return [row for row in snapshot['nftables'] if not is_local(row)]
 unrelated_nft_changed=without_local(first)!=without_local(second)
 local_display_transition=(not unrelated_nft_changed and local_rows(first)!=local_rows(second))
 if local_display_transition:
  assert f.exact_stopped_local_cgroup_spelling(first,second,{('ip',p.LOCAL_TABLE)})
 proof=p.local_verify_stopping(binding,'a'*32,config_semantic_sha256='d'*64)
 assert proof['cgroup_inode']==D['inode']
 try:p.local_verify(binding,'a'*32,config_semantic_sha256='d'*64);raise AssertionError('runtime accepted dead cgroup')
 except FileNotFoundError:pass
 lock=open(root/'guard.lock','xb')
 @contextlib.contextmanager
 def guard(*, reserve_assessment=False):
  fcntl.flock(lock,fcntl.LOCK_EX)
  try:yield lock.fileno()
  finally:fcntl.flock(lock,fcntl.LOCK_UN)
 installation={'guard_policy_source_sha256':hashlib.sha256(pathlib.Path(p.__file__).read_bytes()).hexdigest()}
 calls=0;tc_failure=None
 def snapshot(*args,**kwargs):
  global calls,tc_failure
  calls+=1
  if calls==1:
   links=json.loads(cmd('ip','-j','-d','link','show'));assert any(r['ifname']=='aegis-tun0'for r in links)
   cmd('ip','link','del','aegis-tun0')
   try:m.run('tc','-j','qdisc','show','dev','aegis-tun0');raise AssertionError('tc accepted deleted TUN')
   except m.PolicyInputUnavailable as e:tc_failure=m.refusal_coordinates(e);raise
  p.local_verify_stopping(binding,'a'*32,config_semantic_sha256='d'*64)
  return {'fresh':calls}
 with socket.socket(socket.AF_NETLINK,socket.SOCK_RAW|socket.SOCK_NONBLOCK,12)as peer:
  peer.bind((0,0));generation=m.get_generation(peer)
  with patch.object(m,'guard_lock',side_effect=guard),patch.object(m,'state',return_value=(raw,{'armed':'1','uplink':'eth0'})),patch.object(m,'assessment_options',return_value={}),patch.object(m,'assess_foreign_policy',side_effect=snapshot),patch.object(m,'cgroup_members'),patch.object(m,'_BORROW_CONTEXT',None),patch.object(m,'actor_module',return_value=SimpleNamespace(_own_source=lambda:installation)):
   fresh=m.stable_assessment(peer)
   with patch.object(m,'_BORROW_CONTEXT',{'private_unit':'aegis-auto@'+'f'*64+'.service'}):
    try:m.owned_tun_stop_proven();raise AssertionError('foreign borrowed Stop owner accepted')
    except m.ForeignPolicyRefused:pass
  assert fresh=={'fresh':2} and m.get_generation(peer)==generation
 assert tc_failure['policy_input']=='tc_qdisc' and tc_failure['input_failure']=='missing_device'
 cmd('nft','add','rule','inet',p.TABLE,'output','accept')
 try:p.local_verify_stopping(binding,'a'*32,config_semantic_sha256='d'*64);raise AssertionError('foreign ACCEPT admitted')
 except p.PolicyRefused:pass
 # Exercise the actual shell apply_rules with the real deny/held-OFD reader.
 # Only installed source discovery and unrelated selected-relay/foreign-policy
 # fixtures are substituted; no kernel policy or deny result is mocked.
 import os
 helper=root/'guardian-probe.py'
 bootstrap='''import sys,pathlib,importlib.util,json
sys.path.insert(0,LIB)
import aegis_auto_guard_policy as p
spec=importlib.util.spec_from_file_location('idempotent_guardian',pathlib.Path(ORIGIN)/'aegis_auto_guardian.py')
g=importlib.util.module_from_spec(spec);sys.modules[spec.name]=g;spec.loader.exec_module(g)
p.SCOPED_PARENT=pathlib.Path(ROOT);g.GUARD_LOCK=pathlib.Path(ROOT)/'guard.lock';g.STOP_INTENT=pathlib.Path(ROOT)/'auto-stop-intent.json'
g.own_source=lambda:None
g.verified_module=lambda path,name:p
assert sys.argv[1:]==['stopping-deny-readback','9']
print(json.dumps(g.stopping_deny_readback(9)))
'''.replace('LIB',repr(str(lib))).replace('ORIGIN',repr(sys.argv[1])).replace('ROOT',repr(str(root)))
 helper.write_text(bootstrap);helper.chmod(0o500)
 marker=root/'installed.marker';marker.write_text('{}');marker.chmod(0o600)
 body='apply_rules() {'+source.split('\napply_rules() {',1)[1].split('\n}\n\nguard_table_shape_present() {',1)[0]+'\n}\n'
 shape='guard_table_shape_present() {'+source.split('\nguard_table_shape_present() {',1)[1].split('\n}\n\n\ntable_present()',1)[0]+'\n}\n'
 # Function-only fixture entry points grant no packet permission.
 prelude='set -eu\nselected_relay_prepare() { :; }\nselected_relay_finish() { :; }\nverify_v2_bindings() { :; }\nforeign_assessment() { :; }\nfail() { exit 91; }\n'
 environment=dict(env,ACTION='block',STATE='/var/lib/aegis-install/client/device-guard.conf',
  AUTO_INSTALL=str(marker),AUTO_GUARDIAN=str(helper),AEGIS_AUTO_HELD_GUARD_FD='9',
  cgroup_path='',manager_path='',selected_relay_script='',selected_relay_stop_after_block='0')
 os.dup2(lock.fileno(),9);fcntl.flock(9,fcntl.LOCK_EX)
 def generation():
  with socket.socket(socket.AF_NETLINK,socket.SOCK_RAW|socket.SOCK_NONBLOCK,12)as peer:
   peer.bind((0,0));return m.get_generation(peer)
 def block():
  result=subprocess.run(['/bin/bash','--noprofile','--norc','-c',prelude+shape+body+'\napply_rules "$1"\n','stand',script.decode()],env=environment,pass_fds=(9,),capture_output=True,timeout=5)
  assert result.returncode==0,result.stderr.decode()
 # Foreign ACCEPT must be repaired through the normal restrictive transaction.
 before_generation=generation();block();assert generation()!=before_generation
 p.verify_stopping_guard(D['unit'],'a'*32)
 verification=subprocess.run(['/usr/bin/python3','-I','-B',str(helper),'stopping-deny-readback','9'],pass_fds=(9,),capture_output=True,timeout=3)
 assert verification.returncode==0,verification.stderr.decode()
 before_generation=generation();block();assert generation()==before_generation
 fcntl.flock(9,fcntl.LOCK_UN);os.close(9)
print(json.dumps({'real_deleted_tun_tc_refused':tc_failure,'fresh_snapshot_passes':calls,'stopped_numeric_local_verified':True,'real_local_display_transition_observed':local_display_transition,'unrelated_nft_changed_during_local_probe':unrelated_nft_changed,'runtime_dead_cgroup_refused':True,'foreign_accept_refused':True,'unchanged_nft_generation':True,'idempotent_block_unchanged_generation':True,'foreign_accept_block_repaired':True}))
"""
            result=subprocess.run(['unshare','--net','/usr/bin/python3','-I','-B','-c',program,str(LIB),json.dumps(data)],capture_output=True,timeout=15)
            self.assertEqual(result.returncode,0,result.stderr.decode(errors='replace'))
            value=json.loads(result.stdout);print(json.dumps(value),flush=True)
            self.assertTrue(value['foreign_accept_refused']);self.assertEqual(value['fresh_snapshot_passes'],2)
            self.assertIs(type(value['real_local_display_transition_observed']),bool)
        finally:
            subprocess.run(['systemctl','stop',unit],capture_output=True,timeout=5)

    def test_real_ra_renewal_preserves_route_and_second_router_refuses(self):
        token=uuid.uuid4().hex[:10];client='agc'+token;router='agr'+token
        namespaces=[]
        try:
            for name in (client,router):run('ip','netns','add',name);namespaces.append(name)
            run('ip','link','add','agvc'+token,'netns',client,'type','veth',
                'peer','name','agvr'+token,'netns',router)
            for name,link,addr in ((client,'agvc'+token,'fe80::2/64'),
                                   (router,'agvr'+token,'fe80::1/64')):
                run('ip','-n',name,'link','set',link,'name','eth0')
                for key,value in (('accept_dad','0'),('accept_ra','2'),('autoconf','0')):
                    run('ip','netns','exec',name,'sysctl','-q','-w','net.ipv6.conf.eth0.'+key+'='+value)
                run('ip','-n',name,'addr','add',addr,'dev','eth0','nodad')
                run('ip','-n',name,'link','set','eth0','up')
                run('ip','-n',name,'link','set','lo','up')
                run('ip','-n',name,'-6','route','add','ff00::/8','dev','eth0')
            def advertise(source,lifetime):
                code="""import socket,struct,sys
s=socket.socket(socket.AF_INET6,socket.SOCK_RAW,socket.IPPROTO_ICMPV6)
i=socket.if_nametoindex('eth0');s.setsockopt(socket.IPPROTO_IPV6,socket.IPV6_MULTICAST_IF,i)
s.setsockopt(socket.IPPROTO_IPV6,socket.IPV6_MULTICAST_HOPS,255)
s.bind((sys.argv[1],0,0,i))
s.sendto(struct.pack('!BBHBBHII',134,0,0,64,0,int(sys.argv[2]),0,0),('ff02::1',0,0,i))
"""
                run('ip','netns','exec',router,'python3','-I','-B','-c',code,source,str(lifetime))
            def snapshot():
                start=time.monotonic_ns()
                # Match the production unfiltered JSON read. iproute2 omits
                # the protocol field when it is also a command-line filter.
                rows=[row for row in json.loads(run('ip','-n',client,'-6','-j','route','show','table','all'))
                      if row.get('protocol')=='ra']
                return start,time.monotonic_ns(),rows
            advertise('fe80::1',12);time.sleep(.15)
            a,b,before=snapshot();self.assertEqual(len(before),1)
            time.sleep(3.1);advertise('fe80::1',20);time.sleep(.15)
            c,d,after=snapshot();self.assertEqual(len(after),1)
            print(json.dumps({'isolated_ra_before':before,'isolated_ra_after':after}),flush=True)
            self.assertGreater(after[0]['expires'],before[0]['expires'])
            self.assertEqual(policy.restore_route_expiry(before,after,a,b,c,d),before)
            # Networkd manages RA prefix routes through RTM_NEWROUTE. Exercise
            # that real kernel expiry update independently of kernel SLAAC.
            prefix_args=('2001:db8:53::/64','dev','eth0','proto','ra','metric','512','expires','40')
            run('ip','-n',client,'-6','route','add',*prefix_args);time.sleep(1.2)
            a,b,before=snapshot();self.assertEqual(len(before),2)
            time.sleep(1.1);run('ip','-n',client,'-6','route','replace',*prefix_args);time.sleep(.15)
            c,d,after=snapshot();self.assertEqual(len(after),2)
            prefix_before=next(row for row in before if row['dst']!='default')
            prefix_after=next(row for row in after if row['dst']!='default')
            self.assertGreater(prefix_after['expires'],prefix_before['expires'])
            print(json.dumps({'managed_prefix_before':prefix_before,'managed_prefix_after':prefix_after}),flush=True)
            self.assertEqual(policy.restore_route_expiry(before,after,a,b,c,d),before)
            run('ip','-n',router,'addr','add','fe80::3/64','dev','eth0','nodad')
            advertise('fe80::3',20);time.sleep(.15)
            c,d,foreign=snapshot();self.assertEqual(len(foreign),3)
            with self.assertRaises(policy.ForeignPolicyRefused):
                policy.restore_route_expiry(before,foreign,a,b,c,d)
        finally:
            for name in reversed(namespaces):run('ip','netns','del',name)

    def test_actual_pid1_rotation_resume_fragment_and_deadline(self):
        name='aegis-qa-rotation-resume-'+uuid.uuid4().hex
        try:
            run('systemd-run','--unit='+name,'--on-active=600s',
                '--timer-property=AccuracySec=1s','--property=Type=oneshot',
                '/usr/bin/systemctl','start','aegis-foreign-policy-monitor.service')
            with patch.object(guardian,'_rotation_monitor_resume_name',return_value=name):
                self.assertTrue(guardian._rotation_monitor_resume_live())
        finally:
            # Stopping the timer collects its never-started transient service.
            run('systemctl','stop',name+'.timer')
            subprocess.run(['systemctl','stop',name+'.service'],capture_output=True,timeout=5)
            subprocess.run(['systemctl','reset-failed',name+'.timer',name+'.service'],capture_output=True,timeout=5)

    def test_registered_rotation_borrows_same_kernel_ofd_and_rejects_mutants(self):
        with tempfile.TemporaryDirectory(prefix='aegis-qa-rotation-',dir='/var/lib') as folder:
            root=Path(folder);state=root/'device-guard.conf';guard=root/'guard.lock';install=root/'install.lock'
            source=root/'incoming/scripts/lib/aegis_installer_auto_v2.py';source.parent.mkdir(parents=True)
            source.write_bytes(b'# retained stand coordinator identity\n');source.chmod(0o444)
            installed=root/'auto-guardian-install.json';installed.write_bytes(b'{}');installed.chmod(0o600)
            for path in (guard,install):path.touch(mode=0o600)
            child_code="""import os,fcntl,sys
for path,target in zip(sys.argv[1:],(9,10)):
 fd=os.open(path,os.O_RDWR);os.dup2(fd,target)
 if fd!=target:os.close(fd)
 fcntl.flock(target,fcntl.LOCK_EX)
print('ready',flush=True);sys.stdin.buffer.read(1)
"""
            child=subprocess.Popen(['/usr/bin/python3','-I','-B','-c',child_code,str(install),str(guard)],
                                   stdin=subprocess.PIPE,stdout=subprocess.PIPE)
            try:
                self.assertEqual(child.stdout.readline(),b'ready\n')
                proc=Path('/proc')/str(child.pid);si=install.stat();gi=guard.stat()
                registration={'pid':child.pid,'birth':int((proc/'stat').read_text().rsplit(')',1)[1].split()[19]),
                    'argv_sha256':hashlib.sha256((proc/'cmdline').read_bytes()).hexdigest(),
                    'exe_sha256':hashlib.sha256((proc/'exe').read_bytes()).hexdigest(),
                    'source':str(source),'source_sha256':hashlib.sha256(source.read_bytes()).hexdigest(),
                    'cgroup':(proc/'cgroup').read_text(),'install_device':si.st_dev,'install_inode':si.st_ino}
                intent={'schema':'aegis_auto_guard_rotation_intent_v1',
                    'boot_id':Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
                    'successor':{'next_public_payload_root':str(root/'incoming')},
                    'guard_device':gi.st_dev,'guard_inode':gi.st_ino,'coordinator':registration,
                    'old_install_sha256':hashlib.sha256(installed.read_bytes()).hexdigest()}
                record=root/'auto-guard-rotation-intent.json'
                def write(value):record.write_text(json.dumps(value));record.chmod(0o600)
                write(intent)
                with patch.object(monitor,'STATE',state),patch.object(monitor,'LOCK',guard), \
                     patch.object(monitor,'INSTALL_LOCK',install),patch.object(monitor,'actor_module',return_value=watchdog), \
                     patch.object(watchdog,'GUARD_LOCK',guard):
                    fd,context=monitor._borrow_rotation_guard()
                    try:
                        self.assertEqual((os.fstat(fd).st_dev,os.fstat(fd).st_ino),(gi.st_dev,gi.st_ino))
                        other=os.open(guard,os.O_RDWR)
                        try:
                            with self.assertRaises(BlockingIOError):fcntl.flock(other,fcntl.LOCK_EX|fcntl.LOCK_NB)
                        finally:os.close(other)
                    finally:os.close(fd);os.close(context['actor_pidfd'])
                    for key,value in (('birth',registration['birth']+1),('argv_sha256','0'*64),
                                      ('exe_sha256','0'*64),('source_sha256','0'*64),
                                      ('install_inode',si.st_ino+1)):
                        changed=json.loads(json.dumps(intent));changed['coordinator'][key]=value;write(changed)
                        with self.subTest(key=key),self.assertRaises(ValueError):monitor._borrow_rotation_guard()
                    changed=json.loads(json.dumps(intent));changed['guard_inode']+=1;write(changed)
                    with self.assertRaises(ValueError):monitor._borrow_rotation_guard()
                    changed=json.loads(json.dumps(intent));del changed['coordinator'];write(changed)
                    self.assertIsNone(monitor._borrow_rotation_guard())
            finally:
                child.stdin.close();child.wait(timeout=5);child.stdout.close()


def watchdog_stand(folder):
    root=Path(folder);guard=root/'guard.lock';guard.touch(mode=0o600)
    helper=root/'helper.sh';marker=root/'ready'
    helper.write_text('printf ready > '+shlex.quote(str(marker))+'\nsleep 60\n');helper.chmod(0o500)
    with patch.object(watchdog,'GUARD_LOCK',guard),patch.object(watchdog,'HELPER',helper):
        block,fd,leaf=watchdog._fresh_block_with_retained_ofd()
        try:
            until=time.monotonic()+3
            while not marker.exists() and time.monotonic()<until:time.sleep(.01)
            assert marker.read_bytes()==b'ready'
            watchdog._guard_identity(fd)
            assert leaf.joinpath('cgroup.procs').read_text().strip()
            other=os.open(guard,os.O_RDWR)
            try:
                try:fcntl.flock(other,fcntl.LOCK_EX|fcntl.LOCK_NB)
                except BlockingIOError:pass
                else:raise AssertionError('retained original OFD was not locked')
            finally:os.close(other)
        finally:watchdog._close_fresh_block(block,fd,leaf)
        assert block.poll() is not None and not leaf.exists()
    (root/'result.json').write_text(json.dumps({'original_ofd_retained':True,'whole_leaf_dead':True}))


if __name__=='__main__':
    if len(sys.argv)==3 and sys.argv[1]=='--watchdog-stand':watchdog_stand(sys.argv[2])
    else:unittest.main()
