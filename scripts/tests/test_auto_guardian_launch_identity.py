"""The installed launch actor must use the sealed new runtime identity."""

import importlib.util
import copy
import hashlib
import json
import io
import os
import pathlib
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from contextlib import ExitStack, redirect_stderr
from unittest.mock import MagicMock, Mock, patch
from types import ModuleType, SimpleNamespace

import fcntl


SOURCE = pathlib.Path(__file__).resolve().parents[1] / "lib/aegis_auto_guardian.py"
SPEC = importlib.util.spec_from_file_location("aegis_auto_guardian", SOURCE)
guardian = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(guardian)
WATCHDOG_SOURCE = SOURCE.with_name("aegis_auto_guardian_watchdog.py")
WATCHDOG_SPEC = importlib.util.spec_from_file_location(
    "aegis_auto_guardian_watchdog", WATCHDOG_SOURCE)
watchdog = importlib.util.module_from_spec(WATCHDOG_SPEC)
sys.modules[WATCHDOG_SPEC.name] = watchdog
WATCHDOG_SPEC.loader.exec_module(watchdog)
LAUNCH_SOURCE = SOURCE.with_name("aegis_auto_launch.py")
LAUNCH_SPEC = importlib.util.spec_from_file_location("aegis_auto_launch", LAUNCH_SOURCE)
launch = importlib.util.module_from_spec(LAUNCH_SPEC)
sys.modules[LAUNCH_SPEC.name] = launch
LAUNCH_SPEC.loader.exec_module(launch)
ROLLBACK_SOURCE = SOURCE.with_name("aegis_auto_trace_rollback.py")
ROLLBACK_SPEC = importlib.util.spec_from_file_location(
    "aegis_auto_trace_rollback", ROLLBACK_SOURCE)
rollback = importlib.util.module_from_spec(ROLLBACK_SPEC)
ROLLBACK_SPEC.loader.exec_module(rollback)
TOPOLOGY_SOURCE = SOURCE.with_name("aegis_auto_witness_topology.py")
TOPOLOGY_SPEC = importlib.util.spec_from_file_location(
    "aegis_auto_witness_topology", TOPOLOGY_SOURCE)
topology = importlib.util.module_from_spec(TOPOLOGY_SPEC)
sys.modules[TOPOLOGY_SPEC.name] = topology
TOPOLOGY_SPEC.loader.exec_module(topology)
SINK_SOURCE = SOURCE.with_name("aegis_auto_sink.py")
SINK_SPEC = importlib.util.spec_from_file_location("aegis_auto_sink", SINK_SOURCE)
sink = importlib.util.module_from_spec(SINK_SPEC)
SINK_SPEC.loader.exec_module(sink)


def header(mode, user, uid, gid, policy):
    return {"mode": mode, "service_uid": 0,
            "runtime_binding": {"identity": {"user": user, "uid": uid,
                                              "gid": gid}, "policy": policy}}


class LaunchRuntimeIdentityTests(unittest.TestCase):
    def test_pid1_read_retries_unavailability_but_not_wrong_identity(self):
        unit='aegis-auto@'+'a'*64+'.service';group='/system.slice/'+unit
        facts={'MainPID':'1234','ControlPID':'0','ControlGroup':group,
               'InvocationID':'b'*32,'ActiveState':'active','SubState':'running'}
        encode=lambda row:''.join(k+'='+v+'\n'for k,v in row.items()).encode()
        failed=subprocess.CompletedProcess([],1,b'',b'Failed to connect to bus: PRIVATE_SENTINEL')
        good=subprocess.CompletedProcess([],0,encode(facts),b'')
        with patch.object(guardian.Path,'read_text',return_value='0::'+group+'\n'), \
             patch.object(guardian.time,'monotonic',return_value=0), \
             patch.object(guardian.subprocess,'run',side_effect=[failed,good])as query, \
             patch.object(guardian.time,'sleep')as pause, \
             redirect_stderr(io.StringIO())as errors:
            self.assertEqual(guardian._launch_unit_identity(unit,1234),facts)
            self.assertEqual(query.call_count,2)
            pause.assert_called_once_with(0.025)
            self.assertTrue(all(0<x.kwargs['timeout']<=2 for x in query.call_args_list))
            self.assertNotIn('PRIVATE_SENTINEL',errors.getvalue())
        wrong=subprocess.CompletedProcess([],0,encode(dict(facts,MainPID='999')),b'')
        with patch.object(guardian.subprocess,'run',return_value=wrong)as query:
            with self.assertRaises(guardian.Refused):guardian._launch_unit_identity(unit,1234)
            query.assert_called_once()

    def test_pid1_read_preserves_one_absolute_deadline_and_output_bound(self):
        unit='aegis-auto@'+'a'*64+'.service'
        failed=subprocess.CompletedProcess([],1,b'',b'Failed to connect to bus')
        with patch.object(guardian.time,'monotonic',side_effect=[0,0,2.1]), \
             patch.object(guardian.subprocess,'run',return_value=failed)as query,redirect_stderr(io.StringIO()):
            with self.assertRaises(guardian.Refused):guardian._launch_unit_identity(unit,1234)
            query.assert_called_once()
        with patch.object(guardian.time,'monotonic',return_value=0), \
             patch.object(guardian.subprocess,'run',return_value=failed)as query, \
             patch.object(guardian.time,'sleep')as pause,redirect_stderr(io.StringIO()):
            with self.assertRaises(guardian.Refused):guardian._launch_unit_identity(unit,1234)
            self.assertEqual(query.call_count,3)
            self.assertEqual(pause.call_count,2)
        failed.stdout=b'x'*4097
        with patch.object(guardian.subprocess,'run',return_value=failed)as query:
            with self.assertRaises(guardian.Refused):guardian._launch_unit_identity(unit,1234)
            query.assert_called_once()

    def test_pid1_read_never_retries_permission_missing_or_unknown_failure(self):
        unit='aegis-auto@'+'a'*64+'.service'
        for stderr in (b'Permission denied', b'Unit not found', b'PRIVATE_SENTINEL'):
            with self.subTest(stderr=stderr), \
                 patch.object(guardian.subprocess,'run',return_value=
                     subprocess.CompletedProcess([],1,b'',stderr))as query, \
                 patch.object(guardian.time,'sleep')as pause, \
                 redirect_stderr(io.StringIO())as errors:
                with self.assertRaises(guardian.Refused):
                    guardian._launch_unit_identity(unit,1234)
                query.assert_called_once()
                pause.assert_not_called()
                self.assertNotIn('PRIVATE_SENTINEL',errors.getvalue())

    def test_live_launch_status_has_only_sealed_identity_groups_and_caps(self):
        good = (b"Name:\taegis-client\nUid:\t998\t998\t998\t998\n"
                b"Gid:\t997\t997\t997\t997\nGroups:\t997\n"
                b"NoNewPrivs:\t1\nCapInh:\t0000000000000000\n"
                b"CapPrm:\t0000000000000000\n"
                b"CapEff:\t0000000000000000\n"
                b"CapBnd:\t0000000000000000\n"
                b"CapAmb:\t0000000000000000\n")
        launch._status_authority(good, 998, 997, "dedicated_none")
        launch._status_authority(good.replace(b"Groups:\t997", b"Groups:\t"),
                                 998, 997, "dedicated_none")
        bind = good.replace(b"0000000000000000", b"0000000000000400")
        launch._status_authority(bind, 998, 997, "dedicated_bind")
        for changed in (
                good.replace(b"Uid:\t998\t998\t998\t998",
                             b"Uid:\t998\t998\t0\t998"),
                good.replace(b"Gid:\t997\t997\t997\t997",
                             b"Gid:\t997\t997\t0\t997"),
                good.replace(b"Groups:\t997", b"Groups:\t997 27"),
                good.replace(b"NoNewPrivs:\t1", b"NoNewPrivs:\t0"),
                good.replace(b"CapEff:\t0000000000000000",
                             b"CapEff:\t0000000000000400"),
                good.replace(b"CapBnd:\t0000000000000000",
                             b"CapBnd:\t0000000000000001"),
                good.replace(b"CapAmb:\t0000000000000000",
                             b"CapAmb:\t0"),
                good + b"Groups:\t997\n",
                good.replace(b"CapAmb:\t0000000000000000\n", b""),
                good.replace(b"NoNewPrivs:\t1", b"NoNewPrivs:\tbad"),
        ):
            with self.subTest(changed=changed), self.assertRaises(launch.LaunchRefused):
                launch._status_authority(changed, 998, 997, "dedicated_none")
        root = (b"Name:\taegis-client\nUid:\t0\t0\t0\t0\n"
                b"Gid:\t0\t0\t0\t0\n")
        launch._status_authority(root, 0, 0, "root")
        with self.assertRaises(launch.LaunchRefused):
            launch._status_authority(root.replace(b"Gid:\t0\t0\t0\t0",
                                                   b"Gid:\t0\t27\t0\t0"),
                                     0, 0, "root")

    def test_live_launch_status_reader_is_bounded_and_closes_fd(self):
        with patch.object(launch.os, "open", return_value=77) as opened, \
             patch.object(launch.os, "read", return_value=b"x" *
                          (launch.STATUS_LIMIT + 1)), \
             patch.object(launch.os, "close") as closed, \
             self.assertRaises(launch.LaunchRefused):
            launch._process_authority(1234, 998, 997, "dedicated_none")
        self.assertEqual(opened.call_args.args[0], "/proc/1234/status")
        closed.assert_called_once_with(77)

    def test_hello_and_confirm_authority_precede_claim_and_lease(self):
        unit = "aegis-auto@" + "a" * 64 + ".service"
        invocation = "1" * 32
        nonce = "2" * 64
        ticket = b"t" * 32
        challenge = b"c" * 32
        proof = hashlib.sha256(ticket + challenge + bytes.fromhex(nonce) +
                               bytes.fromhex(invocation) + unit.encode()).hexdigest()
        hello = f"HELLO 1 {unit} {invocation} {nonce}".encode()
        confirm = b"CONFIRM 1 " + proof.encode()
        facts = {"InvocationID": invocation,
                 "ControlGroup": "/system.slice/" + unit}
        for rejected_at in (1, 2, 3, None):
            with self.subTest(rejected_at=rejected_at):
                channel = Mock()
                channel.family = socket.AF_UNIX
                channel.type = socket.SOCK_SEQPACKET
                channel.sendall = Mock()
                claim = Mock()
                packets = [(hello, 1234, 998, 997, 77),
                           (confirm, 1234, 998, 997, 78)]
                seen = []

                def authority(*args):
                    seen.append(args)
                    if len(seen) == rejected_at:
                        raise launch.LaunchRefused("main_capabilities_changed")

                with patch.object(launch.socket, "socket", return_value=channel), \
                     patch.object(launch, "_packet", side_effect=packets), \
                     patch.object(launch, "_process_authority", side_effect=authority), \
                     patch.object(launch, "_start_tick", return_value=42), \
                     patch.object(launch, "_digest_executable"), \
                     patch.object(launch, "_live", return_value=True), \
                     patch.object(launch.os, "close"), \
                     patch.object(launch.os, "urandom", side_effect=[ticket, challenge]), \
                     patch.object(launch.HeldLaunch, "revalidate"):
                    actor = launch.LaunchActor(
                        19, unit, "f" * 64, 998, 997, "dedicated_none",
                        lambda _unit, _pid: facts, claim)
                    if rejected_at is None:
                        held = actor.accept()
                        self.assertEqual(len(seen), 3)
                        claim.assert_called_once()
                        self.assertTrue(any(call.args[0].startswith(b"LEASE 1 ")
                                            for call in channel.sendall.call_args_list))
                        held.close()
                    else:
                        with self.assertRaises(launch.LaunchRefused):
                            actor.accept()
                        self.assertEqual(len(seen), rejected_at)
                        self.assertEqual(claim.call_count, int(rejected_at == 3))
                        self.assertFalse(any(call.args[0].startswith(b"LEASE 1 ")
                                             for call in channel.sendall.call_args_list))

    def test_launch_watcher_waits_for_owned_stop_before_sending_deny_barrier(self):
        unit='aegis-auto@'+'a'*64+'.service'
        daemon=guardian.Guardian();held=Mock();actor=Mock()
        daemon.main_digests[unit]='f'*64;daemon.watchdogs[unit]=actor
        held.revalidate.side_effect=guardian.Refused('launch_pid1_identity_changed')
        with patch.object(guardian,'_pending_owned_stop',side_effect=[True,guardian.Refused('launch_process_exited')]), \
             patch.object(guardian,'_private_unit_inactive',return_value=True), \
             patch.object(guardian.time,'sleep'),patch.object(guardian.Path,'exists',return_value=False):
            daemon._watch_launch(unit,held)
        actor.revalidate.assert_called_once()
        actor.begin_stop.assert_not_called()
        actor.fail_closed.assert_not_called()
        held.close.assert_called_once()

    def test_owned_stop_wait_has_one_absolute_deadline(self):
        unit='aegis-auto@'+'a'*64+'.service'
        daemon=guardian.Guardian();held=Mock();actor=Mock()
        daemon.main_digests[unit]='f'*64;daemon.watchdogs[unit]=actor
        held.revalidate.side_effect=guardian.Refused('launch_pid1_identity_changed')
        with patch.object(guardian,'_pending_owned_stop',return_value=True), \
             patch.object(guardian,'_private_unit_inactive',side_effect=[False,False]), \
             patch.object(guardian.time,'monotonic',side_effect=[10,23]), \
             patch.object(guardian.time,'sleep'),patch.object(guardian.Path,'exists',return_value=False):
            daemon._watch_launch(unit,held)
        actor.revalidate.assert_called_once()
        actor.fail_closed.assert_not_called()  # the deny-proven barrier below completed
        actor.begin_stop.assert_called_once_with(probe=True)
        held.close.assert_called_once()

    def test_unproven_stop_classification_keeps_restrictive_recovery_available(self):
        unit='aegis-auto@'+'a'*64+'.service'
        daemon=guardian.Guardian();held=Mock();actor=Mock()
        daemon.main_digests[unit]='f'*64;daemon.watchdogs[unit]=actor
        held.revalidate.side_effect=guardian.Refused('launch_pid1_identity_changed')
        actor.begin_stop.return_value=None
        with patch.object(guardian,'_pending_owned_stop',side_effect=guardian.Refused('pending_stop_pid1_changed')), \
             patch.object(guardian,'_private_unit_inactive',return_value=False), \
             patch.object(guardian.Path,'exists',return_value=False),redirect_stderr(io.StringIO()):
            daemon._watch_launch(unit,held)
        actor.begin_stop.assert_called_once_with(probe=True)
        actor.fail_closed.assert_called_once_with('launch_channel_lost')
        held.close.assert_called_once()

    def test_stop_probe_does_not_authorize_pending_deny_and_strict_stop_still_refuses(self):
        journal={'boot_id':'boot','private_unit':'aegis-auto@'+'a'*64+'.service',
                 'invocation_id':'b'*32}
        intent={'schema':'aegis_auto_stop_intent_v1','boot_id':journal['boot_id'],
                'service':journal['private_unit'],'invocation_id':journal['invocation_id'],
                'phase':'pending_deny'}
        with tempfile.TemporaryDirectory()as folder:
            path=pathlib.Path(folder)/'stop.json';path.write_text(json.dumps(intent))
            with patch.object(watchdog,'STOP_INTENT',path), \
                 patch.object(watchdog,'_read_root',side_effect=lambda p:p.read_bytes()), \
                 patch.object(watchdog,'_semantic_blocked',return_value='d'*64)as deny:
                self.assertFalse(watchdog._stop_request_proven({'op':'CLASSIFY_STOP'},journal,committed=True,main_pidfd=9))
                with self.assertRaises(watchdog.Refused):
                    watchdog._stop_request_proven({'op':'BEGIN_STOP'},journal,committed=True,main_pidfd=9)
                deny.assert_not_called()
                intent['phase']='deny_proven';path.write_text(json.dumps(intent))
                for op in ('CLASSIFY_STOP','BEGIN_STOP'):
                    self.assertTrue(watchdog._stop_request_proven({'op':op},journal,committed=True,main_pidfd=9))
                intent['invocation_id']='c'*32;path.write_text(json.dumps(intent))
                with self.assertRaises(watchdog.Refused):
                    watchdog._stop_request_proven({'op':'CLASSIFY_STOP'},journal,committed=True,main_pidfd=9)

    def test_stop_client_only_accepts_exact_negative_reply_for_observational_probe(self):
        client=watchdog.WatchdogClient();client.authority=Mock()
        with patch.object(client,'_live'),patch.object(watchdog,'_send')as send, \
             patch.object(watchdog,'_recv',return_value={'state':'NOT_STOPPING'}):
            self.assertIsNone(client.begin_stop(probe=True))
            send.assert_called_once_with(client.authority,{'op':'CLASSIFY_STOP'})
            with self.assertRaises(watchdog.Refused):client.begin_stop()

    @unittest.skipUnless(sys.platform=='linux' and hasattr(os,'pidfd_open'), 'actual Linux PIDFD/cmdline')
    def test_pending_stop_requires_actual_pinned_control_binary_and_exact_arguments(self):
        import subprocess
        unit='aegis-auto@'+'a'*64+'.service'
        identity=SimpleNamespace(unit=unit,pid=1234,invocation='1'*32,cgroup='/system.slice/'+unit)
        held=Mock(identity=identity)
        with tempfile.TemporaryDirectory()as folder:
            script=pathlib.Path(folder)/'auto-stop-service';script.write_text('import time;time.sleep(20)')
            child=subprocess.Popen([sys.executable,'auto-stop-service',unit],cwd=folder)
            try:
                deadline=time.monotonic()+3
                while time.monotonic()<deadline:
                    raw=pathlib.Path('/proc',str(child.pid),'cmdline').read_bytes()
                    if b'auto-stop-service\0'in raw:break
                    time.sleep(.01)
                facts={'ControlPID':str(child.pid),'InvocationID':identity.invocation,'ControlGroup':identity.cgroup}
                pin=guardian.executable_digest(pathlib.Path('/proc',str(child.pid),'exe'))
                original_read=pathlib.Path.read_text
                def own_cgroup(path,*args,**kwargs):
                    if str(path)==f'/proc/{child.pid}/cgroup':return '0::'+identity.cgroup+'\n'
                    return original_read(path,*args,**kwargs)
                with patch.object(guardian,'_launch_unit_identity',return_value=facts), \
                     patch.object(guardian,'_stop_peer') as peer, \
                     patch.object(guardian.Path,'read_text',own_cgroup), \
                     patch.object(guardian.Path,'exists',return_value=False):
                    self.assertTrue(guardian._pending_owned_stop(unit,held,pin))
                    peer.assert_called_once_with(child.pid,{'unit':unit,'invocation_id':identity.invocation})
                    with self.assertRaises(guardian.Refused):guardian._pending_owned_stop(unit,held,'0'*64)
                    with patch.object(guardian,'_launch_unit_identity',return_value=dict(facts,InvocationID='2'*32)):
                        with self.assertRaises(guardian.Refused):guardian._pending_owned_stop(unit,held,pin)
                    with patch.object(guardian,'_launch_unit_identity',return_value=dict(facts,ControlPID='0')):
                        self.assertFalse(guardian._pending_owned_stop(unit,held,pin))
                    pending=dict(facts,ControlPID='0')
                    with patch.object(guardian,'_launch_unit_identity',side_effect=[pending,facts,facts]):
                        self.assertTrue(guardian._pending_owned_stop(unit,held,pin))
                    changed=dict(facts,InvocationID='2'*32)
                    with patch.object(guardian,'_launch_unit_identity',side_effect=[pending,changed]):
                        with self.assertRaises(guardian.Refused):guardian._pending_owned_stop(unit,held,pin)
            finally:child.terminate();child.wait(timeout=3)

    @unittest.skipUnless(sys.platform=='linux', 'Linux PID1 ControlPID')
    def test_pending_stop_preexec_is_only_a_one_second_transition(self):
        unit='aegis-auto@'+'a'*64+'.service';group='/system.slice/'+unit
        identity=SimpleNamespace(unit=unit,pid=1234,invocation='1'*32,cgroup=group)
        held=Mock(identity=identity)
        facts={'MainPID':'1234','ControlPID':'4321','ControlGroup':group,
               'InvocationID':identity.invocation,'ActiveState':'deactivating','SubState':'stop'}
        executor=SimpleNamespace(st_dev=7,st_ino=8,st_uid=0,
                                 st_mode=stat.S_IFREG|0o755)
        descriptor=os.open('/dev/null',os.O_RDONLY)
        try:
            with patch.object(guardian.Path,'exists',return_value=False), \
                 patch.object(guardian,'_launch_unit_identity',return_value=facts), \
                 patch.object(guardian.os,'pidfd_open',side_effect=lambda *_:os.dup(descriptor)), \
                 patch.object(guardian,'_pid_alive',return_value=True), \
                 patch.object(guardian.Path,'stat',return_value=executor), \
                 patch.object(guardian.Path,'read_text',return_value='0::'+group+'\n'), \
                 patch.object(guardian,'_peer_executable') as executable, \
                 patch.object(guardian,'_stop_peer') as stop:
                self.assertFalse(guardian._pending_owned_stop(unit,held,'f'*64))
                executable.assert_not_called();stop.assert_not_called()
                with patch.object(guardian,'_launch_unit_identity',return_value=dict(
                        facts,InvocationID='2'*32)):
                    with self.assertRaises(guardian.Refused):
                        guardian._pending_owned_stop(unit,held,'f'*64)
                with patch.object(guardian.Path,'read_text',return_value='0::/foreign\n'):
                    with self.assertRaises(guardian.Refused):
                        guardian._pending_owned_stop(unit,held,'f'*64)
        finally:os.close(descriptor)

    def test_held_launch_revalidates_dedicated_process_authority(self):
        unit = "aegis-auto@" + "a" * 64 + ".service"
        identity = launch.LaunchIdentity(unit, 1234, 998, "1" * 32,
                                         "/system.slice/" + unit, 42, "f" * 64)
        facts = {"InvocationID": identity.invocation,
                 "ControlGroup": identity.cgroup}
        channel = Mock()
        channel.fileno.return_value = 19
        watcher = Mock()
        watcher.poll.return_value = []
        held = launch.HeldLaunch(channel, 77, identity,
                                 lambda _unit, _pid: facts, 997,
                                 "dedicated_none")
        with patch.object(launch, "_live", return_value=True), \
             patch.object(launch.select, "poll", return_value=watcher), \
             patch.object(launch, "_start_tick", return_value=42), \
             patch.object(launch, "_process_authority") as authority, \
             patch.object(launch.os, "close"):
            held.revalidate()
            self.assertEqual(authority.call_args_list,
                             [unittest.mock.call(1234, 998, 997, "dedicated_none")] * 2)
            authority.side_effect = [None, launch.LaunchRefused("main_capabilities_changed")]
            with self.assertRaises(launch.LaunchRefused):
                held.revalidate()
            authority.side_effect = launch.LaunchRefused("main_capabilities_changed")
            with self.assertRaises(launch.LaunchRefused):
                held.revalidate()
            held.close()

    def test_scoped_owner_accepts_only_semantically_identical_formatter_successor(self):
        with tempfile.TemporaryDirectory() as path:
            stage_fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
            try:
                info = os.fstat(stage_fd)
                original = {"stage_dev": info.st_dev, "stage_ino": info.st_ino,
                            "private_unit": "aegis-auto@" + "a" * 64 + ".service",
                            "guard_policy_sha256": "b" * 64,
                            "config_sha256_initial": "c" * 64,
                            "config_semantic_sha256": "d" * 64,
                            "interface": "aegisacp0", "ifindex": 7,
                            "listen_ipv4": "10.231.80.1", "listen_port": 15080}
                request = {"private_unit": original["private_unit"]}
                redirect = SimpleNamespace(
                    SCOPED_INTENT=SimpleNamespace(exists=lambda: True),
                    _scoped_read=lambda _path: {"binding": original})
                formatted = dict(original, config_sha256_initial="e" * 64)
                with patch.object(guardian, "verified_module",
                                  return_value=redirect), \
                     patch.object(guardian, "_scoped_config_binding",
                                  return_value=formatted):
                    self.assertEqual(
                        original,
                        guardian._scoped_owner_binding(stage_fd, request,
                                                       "b" * 64))
                changed = dict(formatted, config_semantic_sha256="f" * 64)
                with patch.object(guardian, "verified_module",
                                  return_value=redirect), \
                     patch.object(guardian, "_scoped_config_binding",
                                  return_value=changed), \
                     self.assertRaises(guardian.Refused):
                    guardian._scoped_owner_binding(stage_fd, request,
                                                   "b" * 64)
            finally:
                os.close(stage_fd)

    def test_inverse_retired_markers_need_sealed_archive_and_stop_intent(self):
        unit = "aegis-auto@" + "a" * 64 + ".service"
        original = {"private_unit": unit}
        grant = {"pid": 42, "nonce": "n" * 32,
                 "native_receipt_sha256": "r" * 64,
                 "policy_sha256": "p" * 64}
        may = b"original-may-send-bytes"
        claim = b"original-claim-bytes"
        archive = {"schema": 1, "may_send_hex": may.hex(),
                   "claim_hex": claim.hex(),
                   "may_send_sha256": guardian.digest(may),
                   "claim_sha256": guardian.digest(claim)}
        archive_raw = json.dumps(archive).encode()
        with tempfile.TemporaryDirectory() as path:
            stage_fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
            try:
                info = os.fstat(stage_fd)
                terminal = {
                    "schema": 1, "outcome": "finalized",
                    "stage": [info.st_dev, info.st_ino],
                    "private_unit": unit,
                    "native_guard": {
                        "guardian_pid": grant["pid"],
                        "guardian_nonce": grant["nonce"],
                        "guardian_receipt_sha256":
                        grant["native_receipt_sha256"],
                        "policy_sha256": grant["policy_sha256"]},
                    "marker_archive_sha256": guardian.digest(archive_raw),
                    "may_send_sha256": guardian.digest(may),
                    "claim_sha256": guardian.digest(claim)}
                terminal_raw = json.dumps(terminal).encode()
                intent = {"schema": 1, "kind": "postterminal-stop-intent",
                          "stage": [info.st_dev, info.st_ino],
                          "terminal_sha256": guardian.digest(terminal_raw),
                          "marker_archive_sha256": guardian.digest(archive_raw),
                          "may_send_sha256": guardian.digest(may),
                          "claim_sha256": guardian.digest(claim),
                          "private_unit": unit}
                records = {
                    "receipts/activation-owner/terminal.json": terminal_raw,
                    "receipts/activation-owner/marker-archive.json":
                    archive_raw}
                header = {"phase": "finalized", "leaves": {
                    name: guardian.digest(raw) for name, raw in records.items()}}

                def leaf(_fd, name):
                    if name == "activation-owner-postterminal-stop.json":
                        return json.dumps(intent).encode()
                    raise FileNotFoundError(name)

                with patch.object(guardian, "_stage_leaf", side_effect=leaf), \
                     patch.object(guardian, "_protected_stage_receipt",
                                  side_effect=lambda _fd, name: records[name]):
                    self.assertEqual(
                        guardian._inverse_owner_markers(
                            stage_fd, header, original, grant),
                        ((may, claim), terminal))
                    changed = dict(intent, claim_sha256="0" * 64)
                    with patch.object(guardian, "_stage_leaf",
                                      side_effect=lambda _fd, name:
                                      json.dumps(changed).encode() if
                                      name == "activation-owner-postterminal-stop.json"
                                      else (_ for _ in ()).throw(
                                          FileNotFoundError(name))):
                        with self.assertRaises(guardian.Refused):
                            guardian._inverse_owner_markers(
                                stage_fd, header, original, grant)
            finally:
                os.close(stage_fd)

    def test_inverse_accepts_stopped_captured_stage_only_with_owner_chain(self):
        original = {"transaction_nonce": "n" * 32,
                    "planned_generation": "g" * 64,
                    "mode": "full-wide-tun",
                    "private_unit": "aegis-auto@" + "a" * 64 + ".service"}
        header = {"phase": "metadata", "capture_started": True,
                  "transaction_nonce": original["transaction_nonce"],
                  "planned_generation": original["planned_generation"],
                  "mode": original["mode"],
                  "pending": None}
        effect = {"prior_invocation_id": "1" * 32}
        markers = (b"protected-may-send", b"protected-claim")
        with patch.object(guardian, "_stage"), \
             patch.object(guardian, "_protected_stage_receipt_for_header",
                          return_value=json.dumps(header).encode()), \
             patch.object(guardian, "_inverse_owner_markers",
                          return_value=(markers, None)) as archived, \
             patch.object(guardian, "_claimed_private_unit") as claimed, \
             patch.object(guardian, "_inverse_stop_chain") as stopped:
            guardian._inverse_stage_successor(9, original, {}, effect)
            claimed.assert_called_once_with(
                9, original, {}, original["private_unit"], initial=False,
                marker_bytes=markers)
            stopped.assert_called_once_with(9, original, effect, markers)
            archived.assert_called_once()
        for changed in (dict(header, transaction_nonce="foreign"),
                        dict(header, mode="socks-only")):
            with self.subTest(changed=changed), \
                 patch.object(guardian, "_stage"), \
                 patch.object(guardian, "_protected_stage_receipt_for_header",
                              return_value=json.dumps(changed).encode()), \
                 patch.object(guardian, "_inverse_owner_markers") as archived, \
                 self.assertRaises(guardian.Refused):
                guardian._inverse_stage_successor(9, original, {}, effect)
                archived.assert_not_called()

    def test_inverse_stop_chain_binds_owned_start_and_exact_completed_stop(self):
        unit = "aegis-auto@" + "a" * 64 + ".service"
        original = {"private_unit": unit, "boot_id": "b" * 36}
        effect = {"prior_invocation_id": "1" * 32,
                  "stop_job_id": 9,
                  "stop_job_path": "/org/freedesktop/systemd1/job/9"}
        may = json.dumps({"commitments": {"pid1_socket": [1, 2],
                                           "pid1_netns": 5}}).encode()
        claim = b"protected-claim"
        submitted = {"schema": 1, "kind": "owned-start-submitted",
                     "may_send_sha256": guardian.digest(may),
                     "claim_sha256": guardian.digest(claim),
                     "unit": unit, "boot_id": original["boot_id"],
                     "pid1_socket": [1, 2], "pid1_netns": 5,
                     "job_id": 4,
                     "job_path": "/org/freedesktop/systemd1/job/4"}
        submitted_raw = json.dumps(submitted).encode()
        completed = {"schema": 1, "kind": "owned-start-completed",
                     "submitted_sha256": guardian.digest(submitted_raw),
                     "unit": unit, "job_id": 4,
                     "job_path": submitted["job_path"],
                     "invocation_id": effect["prior_invocation_id"]}
        completed_raw = json.dumps(completed).encode()
        stop = {"schema": 1, "kind": "owned-stop-submitted",
                "completed_start_sha256": guardian.digest(completed_raw),
                "unit": unit, "boot_id": original["boot_id"],
                "pid1_socket": [1, 2], "pid1_netns": 5,
                "job_id": effect["stop_job_id"],
                "job_path": effect["stop_job_path"]}
        stop_raw = json.dumps(stop).encode()
        done = {"schema": 1, "kind": "owned-stop-completed",
                "stop_submitted_sha256": guardian.digest(stop_raw),
                "unit": unit, "job_id": effect["stop_job_id"],
                "job_path": effect["stop_job_path"],
                "prior_invocation_id": effect["prior_invocation_id"]}
        records = {"submitted.json": submitted_raw,
                   "completed.json": completed_raw,
                   "stop-submitted.json": stop_raw,
                   "stop-completed.json": json.dumps(done).encode()}

        def read(_fd, name):
            return records[name.rsplit("/", 1)[-1]]

        with patch.object(guardian, "_protected_stage_receipt",
                          side_effect=read):
            guardian._inverse_stop_chain(9, original, effect, (may, claim))
            with self.assertRaises(guardian.Refused):
                guardian._inverse_stop_chain(
                    9, original, dict(effect, stop_job_id=10), (may, claim))

    def test_capture_revalidate_before_header_mark_keeps_initial_sha(self):
        initial = {"phase": "metadata", "capture_started": False}
        raw = json.dumps(initial).encode()
        request = {"header_sha256": guardian.digest(raw),
                   "private_unit": "aegis-auto@" + "a" * 64 + ".service"}
        with patch.object(guardian, "_protected_stage_receipt_for_header",
                          return_value=raw), \
             patch.object(guardian, "_claimed_private_unit") as claimed:
            guardian._capture_stage_successor(9, initial, request, {},
                                              {"sha256": "a" * 64})
            claimed.assert_called_once_with(9, request, {},
                                            request["private_unit"])
        with patch.object(guardian, "_protected_stage_receipt_for_header",
                          return_value=json.dumps(dict(initial, phase="finalized")).encode()), \
             patch.object(guardian, "_claimed_private_unit"), \
             patch.object(guardian, "_protected_stage_receipt",
                          side_effect=guardian.Refused("no_consumed_receipt")):
            with self.assertRaises(guardian.Refused):
                guardian._capture_stage_successor(9, initial, request, {},
                                                  {"sha256": "a" * 64})

    def test_wide_capture_metadata_transition_needs_live_native_proof(self):
        unit = "aegis-auto@" + "a" * 64 + ".service"
        request = {"mode": "wide-redirect-safe", "private_unit": unit,
                   "transaction_nonce": "n" * 32}
        identity = SimpleNamespace(invocation="1" * 32)
        initial = {"phase": "metadata", "capture_started": False,
                   "mode": "wide-redirect-safe"}
        captured = {"unit": unit, "nonce": request["transaction_nonce"],
                    "invocation": identity.invocation, "sha256": "a" * 64}
        successor = dict(initial, capture_started=True)

        def admit(header, state):
            with patch.object(guardian, "_claimed_launch_unit"), \
                 patch.object(guardian, "_protected_stage_receipt_for_header",
                              return_value=json.dumps(header).encode()):
                guardian._launch_captured_metadata_successor(
                    9, initial, request, "t" * 64, {}, identity, state)

        admit(successor, captured)
        for changed, state in ((successor, None),
                               (dict(successor, phase="finalized"), captured),
                               (dict(successor, service_uid=0), captured),
                               (successor, dict(captured, invocation="2" * 32))):
            with self.subTest(changed=changed, state=state), \
                 self.assertRaises(guardian.Refused):
                admit(changed, state)

    def test_owned_finalized_successor_keeps_original_claim_and_main(self):
        unit_name = "aegis-auto@" + "a" * 64 + ".service"
        request = {"transaction_nonce": "n" * 32,
                   "planned_generation": "g" * 64,
                   "private_unit": unit_name, "mode": "socks-only",
                   "boot_id": "b" * 36}
        ticket = "t" * 64
        invocation = "1" * 32
        identity = SimpleNamespace(pid=1234, uid=998, start_tick=5678,
                                   invocation=invocation,
                                   cgroup="/system.slice/" + unit_name)
        original = {"phase": "metadata", "mode": "socks-only",
                    "transaction_nonce": request["transaction_nonce"],
                    "planned_generation": request["planned_generation"],
                    "input_generation": "q" * 64,
                    "pending": None, "unit_pending": None,
                    "render_recipe": "accepted/render-recipe.json",
                    "leaves": {"accepted/install-receipt/installed-generation.json":
                               "i" * 64},
                    "current_records": {}, "active_records": {},
                    "runtime_binding": {"identity": {"gid": 998}},
                    "capture_started": False}
        active = "records/active-service/" + "a" * 32 + ".json"
        evidence = {"schema": 2, "unit_name": unit_name,
                    "nonce": request["transaction_nonce"],
                    "input_generation": original["input_generation"],
                    "planned_generation": request["planned_generation"],
                    "policy_generation": "p" * 64,
                    "installed_generation": "i" * 64,
                    "ticks": identity.start_tick,
                    "unit": {"pid": identity.pid,
                             "uid": identity.uid, "gid": 998,
                             "invocation": identity.invocation,
                             "cgroup": identity.cgroup}}
        may = json.dumps({"commitments": {"policy_generation": "p" * 64,
                                          "pid1_socket": [7, 8],
                                          "pid1_netns": 9}}).encode()
        claim = b"source-bound-claim"
        submitted = {"schema": 1, "kind": "owned-start-submitted",
                     "may_send_sha256": guardian.digest(may),
                     "claim_sha256": guardian.digest(claim),
                     "unit": unit_name, "boot_id": request["boot_id"],
                     "pid1_socket": [7, 8], "pid1_netns": 9,
                     "job_id": 4, "job_path": "/org/freedesktop/systemd1/job/4"}
        submitted_raw = json.dumps(submitted).encode()
        completed = {"schema": 1, "kind": "owned-start-completed",
                     "submitted_sha256": guardian.digest(submitted_raw),
                     "unit": unit_name, "job_id": 4,
                     "job_path": submitted["job_path"],
                     "invocation_id": invocation}
        completed_raw = json.dumps(completed).encode()
        consumed = {"schema": 1, "kind": "owned-launch-consumed",
                    "completed_sha256": guardian.digest(completed_raw),
                    "ticket_sha256": ticket, "private_unit": unit_name,
                    "invocation_id": invocation, "main_pid": identity.pid,
                    "main_start_tick": identity.start_tick,
                    "guardian_pid": os.getpid(),
                    "guardian_invocation_id": invocation}
        records = {active: json.dumps(evidence).encode(),
                   "accepted/final-render-recipe.json": b"sealed-recipe",
                   "receipts/activation-owner/submitted.json": submitted_raw,
                   "receipts/activation-owner/completed.json": completed_raw,
                   "receipts/activation-owner/launch-consumed.json":
                   json.dumps(consumed).encode()}
        final = copy.deepcopy(original)
        final["phase"] = "finalized"
        final["render_recipe"] = "accepted/final-render-recipe.json"
        final["leaves"].update({key: guardian.digest(records[key]) for key in
                                (active, "accepted/final-render-recipe.json")})

        def admit(candidate, changed_records=records, *, stage_fd=9,
                  capture_state=None):
            with patch.object(guardian, "_stage", return_value=(12, 34)), \
                 patch.object(guardian, "_claimed_launch_unit"), \
                 patch.object(guardian, "_protected_stage_receipt_for_header",
                              return_value=json.dumps(candidate).encode()), \
                 patch.object(guardian, "_protected_stage_receipt",
                              side_effect=lambda _fd, name: changed_records[name]), \
                 patch.object(guardian, "_final_render_recipe_digest",
                              return_value=guardian.digest(
                                  records["accepted/final-render-recipe.json"])), \
                 patch.object(guardian.os, "fstat", side_effect=lambda _fd:
                              SimpleNamespace(st_mode=directory.st_mode,
                                              st_uid=0, st_dev=directory.st_dev,
                                              st_ino=directory.st_ino)), \
                 patch.object(guardian, "_stage_leaf",
                              side_effect=lambda _fd, name: may if "may-send" in name
                              else claim):
                guardian._launch_projection_successor(
                    stage_fd, original, request, ticket, None, identity,
                    invocation, capture_state)

        admit(final)
        for changed in (
                {**final, "phase": "metadata"},
                {**final, "service_uid": 0},
                {**final, "leaves": {**final["leaves"], active: "0" * 64}}):
            with self.subTest(changed=changed), self.assertRaises(guardian.Refused):
                admit(changed)
        changed_records = dict(records)
        changed_consumed = dict(consumed, main_pid=9999)
        changed_records["receipts/activation-owner/launch-consumed.json"] = \
            json.dumps(changed_consumed).encode()
        with self.assertRaises(guardian.Refused):
            admit(final, changed_records)

        # The wide successor uses the real config-projection directory inode,
        # not the stage root inode, and matches the source-owned receipt chain.
        with tempfile.TemporaryDirectory() as stage_path:
            projection_path = pathlib.Path(stage_path) / "receipts/config-projection"
            projection_path.mkdir(parents=True)
            directory = os.stat(projection_path)
            stage_fd = os.open(stage_path, os.O_RDONLY | os.O_DIRECTORY)
            try:
                request["mode"] = "full-wide-tun"
                original["mode"] = "full-wide-tun"
                original["capture_started"] = False
                old_path = "receipts/config-config/publication-receipt.json"
                old_raw = json.dumps({"kind": "publication", "intent": {"x": 1},
                                      "current": {"y": 2}}).encode()
                old_sha = guardian.digest(old_raw)
                original["current_records"] = {
                    old_path: {"role": "config", "phase": "config",
                               "sha256": old_sha}}
                original["active_records"] = {"config": old_path}
                projected_path = "receipts/config-projection/projection-receipt.json"
                h = guardian.hashlib.sha256(b"aegis-auto-publication-chain-v1\0")
                for value in (request["transaction_nonce"],
                              original["input_generation"],
                              request["planned_generation"], "config",
                              "projection", old_sha):
                    encoded = value.encode()
                    h.update(len(encoded).to_bytes(8, "big"))
                    h.update(encoded)
                chain = h.hexdigest()
                projected_raw = json.dumps({
                    "kind": "projection", "base_record_sha256": old_sha,
                    "intent": {"x": 1}, "base_current": {"y": 2},
                    "binding": {"transaction_stage": {"dev": directory.st_dev,
                                                       "ino": directory.st_ino},
                                "transaction_nonce": request["transaction_nonce"],
                                "phase": "projection", "chain_sha256": chain}}).encode()
                records[old_path] = old_raw
                records[projected_path] = projected_raw
                wide = copy.deepcopy(original)
                wide["phase"] = "finalized"
                wide["capture_started"] = True
                wide["render_recipe"] = "accepted/final-render-recipe.json"
                wide["leaves"].update({key: guardian.digest(records[key]) for key in
                                       (active, "accepted/final-render-recipe.json")})
                wide["current_records"][projected_path] = {
                    "role": "config", "phase": "projection",
                    "predecessor_sha256": old_sha, "sha256": guardian.digest(projected_raw),
                    "stage_dev": directory.st_dev, "stage_ino": directory.st_ino,
                    "chain_sha256": chain}
                wide["active_records"]["config"] = projected_path
                capture_state = {"unit": unit_name,
                                 "nonce": request["transaction_nonce"],
                                 "invocation": invocation,
                                 "sha256": "a" * 64}
                admit(wide, stage_fd=stage_fd, capture_state=capture_state)
                with self.assertRaises(guardian.Refused):
                    admit(dict(wide, current_records={**wide["current_records"],
                         projected_path: {**wide["current_records"][projected_path],
                                          "chain_sha256": "0" * 64}}),
                         stage_fd=stage_fd, capture_state=capture_state)
            finally:
                os.close(stage_fd)

    def test_new_dedicated_actor_uses_sealed_uid_for_both_admitted_accounts(self):
        for user, uid in (("aegis", 997), ("aegis-svc", 998)):
            for mode, policy in (("socks-only", "dedicated_none"),
                                 ("socks-only", "dedicated_bind"),
                                 ("wide-redirect-safe", "dedicated_bind")):
                with self.subTest(user=user, mode=mode, policy=policy):
                    self.assertEqual(
                        guardian._launch_runtime_uid(
                            header(mode, user, uid, uid, policy), mode), uid)

    def test_root_actor_only_with_root_policy_and_matching_mode(self):
        for mode in ("socks-only", "full-wide-tun"):
            self.assertEqual(guardian._launch_runtime_uid(
                header(mode, "root", 0, 0, "root"), mode), 0)
        for data, mode in ((header("socks-only", "root", 0, 0,
                                   "dedicated_none"), "socks-only"),
                           (header("full-wide-tun", "aegis", 997, 997,
                                   "dedicated_bind"), "full-wide-tun"),
                           (header("socks-only", "root", 0, 0, "root"),
                            "wide-redirect-safe")):
            with self.subTest(data=data, mode=mode), self.assertRaises(guardian.Refused):
                guardian._launch_runtime_uid(data, mode)

    def test_foreign_or_non_system_dedicated_actor_refused(self):
        for user, uid, gid, policy in (("foreign", 997, 997, "dedicated_none"),
                                       ("aegis", 0, 0, "dedicated_none"),
                                       ("aegis-svc", 1000, 1000,
                                        "dedicated_none"),
                                       ("aegis", 997, 0, "dedicated_none"),
                                       ("aegis", 997, 997, "root")):
            with self.subTest(user=user, uid=uid, gid=gid, policy=policy), \
                    self.assertRaises(guardian.Refused):
                guardian._launch_runtime_uid(
                    header("socks-only", user, uid, gid, policy), "socks-only")
        with self.assertRaises(guardian.Refused):
            guardian._launch_runtime_uid(
                header("wide-redirect-safe", "aegis", 997, 997,
                       "dedicated_none"), "wide-redirect-safe")

    def test_worker_refusal_journal_is_bounded_and_excludes_exception_data(self):
        guardian_instance = guardian.Guardian()
        peer = Mock()
        output = io.StringIO()
        with patch.object(guardian_instance, "serve_one",
                          side_effect=guardian.Refused("stage_header_changed")), \
             redirect_stderr(output):
            guardian_instance._serve_worker(peer)
        self.assertEqual(output.getvalue(),
                         "aegis_auto_guardian_request_refused:stage_header_changed\n")
        peer.close.assert_called_once_with()

        for error, expected in (
                (guardian.Refused("launch_one_use_claim_missing"),
                 "launch_one_use_claim_missing"),
                (guardian.Refused("invalid_launch_probe"),
                 "invalid_launch_probe"),
                (guardian.Refused("launch_terminal_handoff_not_owned"),
                 "launch_terminal_handoff_not_owned"),
                (guardian.Refused("secret/path"), "refused_unclassified"),
                (guardian.Refused("SecretToken123"), "refused_unclassified"),
                (guardian.Refused("x" * 97), "refused_unclassified"),
                (launch.LaunchRefused("invalid_main_hello"),
                 "launch_actor_invalid_main_hello"),
                (launch.LaunchRefused("SecretToken123"),
                 "launch_actor_unclassified"),
                (RuntimeError("invalid_main_hello"),
                 "runtime_error source=unknown line=0"),
                (OSError("private-key-contents"),
                 "os_error errno=0 source=unknown line=0")):
            peer.reset_mock()
            output = io.StringIO()
            with patch.object(guardian_instance, "serve_one", side_effect=error), \
                 redirect_stderr(output):
                guardian_instance._serve_worker(peer)
            self.assertEqual(output.getvalue(),
                             "aegis_auto_guardian_request_refused:" + expected + "\n")
            peer.close.assert_called_once_with()

    def test_os_error_journal_omits_private_data_and_external_source(self):
        guardian_instance = guardian.Guardian()
        peer = Mock()
        pinned = {}
        exec(compile("def fail(*_args):\n"
                     "    private_token = 'private-key-contents'\n"
                     "    raise OSError(2, private_token)\n",
                     str(guardian.TOPOLOGY_SOURCE), "exec"), pinned)
        output = io.StringIO()
        with patch.object(guardian_instance, "serve_one",
                          side_effect=pinned["fail"]), redirect_stderr(output):
            guardian_instance._serve_worker(peer)
        self.assertEqual(output.getvalue(),
                         "aegis_auto_guardian_request_refused:os_error "
                         "errno=2 source=topology line=3\n")
        self.assertNotIn("private-key-contents", output.getvalue())
        self.assertNotIn(str(guardian.TOPOLOGY_SOURCE), output.getvalue())

        external = {}
        secret_path = "/private/secret-key-material.py"
        exec(compile("def fail(*_args):\n"
                     "    raise OSError(13, 'private-key-contents')\n",
                     secret_path, "exec"), external)
        output = io.StringIO()
        with patch.object(guardian_instance, "serve_one",
                          side_effect=external["fail"]), redirect_stderr(output):
            guardian_instance._serve_worker(peer)
        self.assertEqual(output.getvalue(),
                         "aegis_auto_guardian_request_refused:os_error "
                         "errno=13 source=unknown line=0\n")
        self.assertNotIn(secret_path, output.getvalue())
        self.assertNotIn("private-key-contents", output.getvalue())

    def test_value_refusal_logs_only_pinned_foreign_policy_callsite(self):
        for path, source in ((guardian.FOREIGN_SOURCE, "foreign_policy"),
                             (guardian.WITNESS, "witness")):
            compiled = {}
            exec(compile("def need(value, reason):\n"
                         "    if not value:\n"
                         "        raise ValueError(reason)\n"
                         "\n"
                         "def fail(*_args):\n"
                         "    need(False, 'private-key-contents')\n",
                         str(path), "exec"), compiled)
            instance = guardian.Guardian()
            output = io.StringIO()
            with patch.object(instance, "serve_one", side_effect=compiled["fail"]), redirect_stderr(output):
                instance._serve_worker(Mock())
            self.assertEqual(output.getvalue(),
                             "aegis_auto_guardian_request_refused:value_error "
                             f"source={source} line=6\n")
            self.assertNotIn("private-key-contents", output.getvalue())

    def test_runtime_refusal_logs_pinned_callsite_without_private_reason(self):
        compiled = {"Refused": topology.Refused}
        exec(compile("def need(value, reason):\n"
                     "    if not value:\n"
                     "        raise Refused(reason)\n"
                     "\n"
                     "def fail(*_args):\n"
                     "    need(False, 'private-key-contents')\n",
                     str(guardian.TOPOLOGY_SOURCE), "exec"), compiled)
        guardian_instance = guardian.Guardian()
        output = io.StringIO()
        with patch.object(guardian_instance, "serve_one",
                          side_effect=compiled["fail"]), redirect_stderr(output):
            guardian_instance._serve_worker(Mock())
        self.assertEqual(output.getvalue(),
                         "aegis_auto_guardian_request_refused:runtime_error "
                         "source=topology line=6\n")
        self.assertNotIn("private-key-contents", output.getvalue())
        self.assertNotIn(str(guardian.TOPOLOGY_SOURCE), output.getvalue())

        try:
            compiled["fail"]()
        except topology.Refused as error:
            output = io.StringIO()
            with redirect_stderr(output):
                topology._log_request_refusal(error)
        else:
            self.fail("pinned topology refusal was not raised")
        self.assertEqual(output.getvalue(),
                         "aegis_auto_witness_topology_request_refused:refused "
                         "errno=0 source=topology line=6\n")
        self.assertNotIn("private-key-contents", output.getvalue())

        external = {}
        secret_path = "/private/secret-runtime-source.py"
        exec(compile("def fail(*_args):\n"
                     "    raise RuntimeError('private-key-contents')\n",
                     secret_path, "exec"), external)
        output = io.StringIO()
        with patch.object(guardian_instance, "serve_one",
                          side_effect=external["fail"]), redirect_stderr(output):
            guardian_instance._serve_worker(Mock())
        self.assertEqual(output.getvalue(),
                         "aegis_auto_guardian_request_refused:runtime_error "
                         "source=unknown line=0\n")
        self.assertNotIn(secret_path, output.getvalue())
        self.assertNotIn("private-key-contents", output.getvalue())

    def test_endpoint_and_capture_refusals_log_only_pinned_coordinates(self):
        for path, label in ((guardian.ENDPOINT_SOURCE, "endpoint"),
                            (guardian.CAPTURE_SOURCE, "capture"),
                            (guardian.CAPTURE_TOPOLOGY_SOURCE, "capture_topology")):
            with self.subTest(source=label):
                compiled = {}
                exec(compile("def _need(value, reason):\n"
                             "    if not value:\n"
                             "        raise RuntimeError(reason)\n"
                             "\n"
                             "def fail(*_args):\n"
                             "    _need(False, 'private-key-contents')\n",
                             str(path), "exec"), compiled)
                instance = guardian.Guardian()
                output = io.StringIO()
                with patch.object(instance, "serve_one",
                                  side_effect=compiled["fail"]), redirect_stderr(output):
                    instance._serve_worker(Mock())
                self.assertEqual(output.getvalue(),
                                 "aegis_auto_guardian_request_refused:runtime_error "
                                 f"source={label} line=6\n")
                self.assertNotIn("private-key-contents", output.getvalue())
                self.assertNotIn(str(path), output.getvalue())

    def test_unclassified_and_unexpected_locations_omit_private_data(self):
        compiled = {"Refused": guardian.Refused}
        exec(compile("def need(value, reason):\n"
                     "    if not value:\n"
                     "        raise Refused(reason)\n"
                     "\n"
                     "def unclassified(*_args):\n"
                     "    need(False, 'private-key-contents')\n"
                     "\n"
                     "def unexpected(*_args):\n"
                     "    private_token = 'private-key-contents'\n"
                     "    raise TypeError(private_token)\n",
                     str(guardian.POLICY_SOURCE), "exec"), compiled)
        instance = guardian.Guardian()
        for method, reason, line in (("unclassified", "refused_unclassified", 6),
                                     ("unexpected", "unexpected_exception", 10)):
            with self.subTest(reason=reason):
                output = io.StringIO()
                with patch.object(instance, "serve_one",
                                  side_effect=compiled[method]), redirect_stderr(output):
                    instance._serve_worker(Mock())
                self.assertEqual(output.getvalue(),
                                 "aegis_auto_guardian_request_refused:" + reason +
                                 f" source=policy line={line}\n")
                self.assertNotIn("private-key-contents", output.getvalue())
                self.assertNotIn(str(guardian.POLICY_SOURCE), output.getvalue())


class IndependentSinkLifetimeTests(unittest.TestCase):
    def test_default_complete_returns_but_witness_hold_refuses_closed_or_reused_peer(self):
        held, owner = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            sink._completion_lifetime(held, False, time.monotonic() + 1)
            owner.send(b"unexpected-after-complete")
            with self.assertRaisesRegex(sink.Refused,
                                        "witness_sink_control_closed_or_reused"):
                sink._completion_lifetime(held, True, time.monotonic() + 1)
        finally:
            held.close()
            owner.close()
        held, owner = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            owner.close()
            with self.assertRaisesRegex(sink.Refused,
                                        "witness_sink_control_closed_or_reused"):
                sink._completion_lifetime(held, True, time.monotonic() + 1)
        finally:
            held.close()

    def test_witness_hold_uses_original_absolute_deadline(self):
        held, owner = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            start = time.monotonic()
            with self.assertRaisesRegex(sink.Refused, "witness_sink_lease_expired"):
                sink._completion_lifetime(held, True, start + 0.03)
            self.assertLess(time.monotonic() - start, 0.5)
        finally:
            held.close()
            owner.close()

    def test_authoritative_cleanup_requires_live_sink_and_exact_kill_exit(self):
        process = Mock()
        process.poll.return_value = 0
        with self.assertRaisesRegex(topology.Refused,
                                    "independent_sink_exited_before_cleanup"):
            topology._terminate_live_sink(process)
        process.kill.assert_not_called()
        process.poll.return_value = None
        process.wait.return_value = 0
        with self.assertRaisesRegex(topology.Refused,
                                    "independent_sink_cleanup_exit_mismatch"):
            topology._terminate_live_sink(process)
        process.wait.return_value = -topology.signal.SIGKILL
        topology._terminate_live_sink(process)


class RollbackActorReadinessTests(unittest.TestCase):
    def test_pid1_ready_notification_is_delivered_or_refused(self):
        class NotifySocket:
            def __init__(self, sender, *, connect_error=False):
                self.sender = sender
                self.connect_error = connect_error
                self.address = None

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def connect(self, address):
                if self.connect_error:
                    raise FileNotFoundError(2, "notify socket missing")
                self.address = address

            def send(self, raw):
                return self.sender.send(raw)

        sender, receiver = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
        with sender, receiver:
            notify = NotifySocket(sender)
            with patch.object(rollback.socket, "socket", return_value=notify), \
                 patch.dict(os.environ, {"NOTIFY_SOCKET": "@aegis-test"}):
                rollback._notify_ready()
            self.assertEqual(notify.address, "\0aegis-test")
            self.assertEqual(receiver.recv(32), b"READY=1")

            missing = NotifySocket(sender, connect_error=True)
            with patch.object(rollback.socket, "socket", return_value=missing), \
                 patch.dict(os.environ, {"NOTIFY_SOCKET": "@missing"}):
                with self.assertRaises(OSError):
                    rollback._notify_ready()
            with patch.dict(os.environ, {"NOTIFY_SOCKET": ""}):
                with self.assertRaises(rollback.Refused):
                    rollback._notify_ready()


class HeldFlockReadbackTests(unittest.TestCase):
    def test_exact_whole_inode_and_lock_type(self):
        with tempfile.TemporaryFile() as source:
            identity = os.fstat(source.fileno())
            inode = (f"{os.major(identity.st_dev):02x}:"
                     f"{os.minor(identity.st_dev):02x}:{identity.st_ino}")
            line = f"lock:\t1: FLOCK  ADVISORY  WRITE {os.getpid()} {inode} 0 EOF\n"
            for module in (guardian, watchdog):
                self.assertTrue(module._exclusive_flock_fdinfo(line, identity))
                for changed in (line.replace("FLOCK", "POSIX"),
                                line.replace("FLOCK", "OFDLCK"),
                                line.replace("WRITE", "READ"),
                                line.replace("0 EOF", "1 EOF"),
                                line.replace("1: FLOCK", "1: -> FLOCK"),
                                line.replace(inode, inode + "9"),
                                line + line):
                    with self.subTest(module=module.__name__, changed=changed):
                        self.assertFalse(
                            module._exclusive_flock_fdinfo(changed, identity))

    @unittest.skipUnless(sys.platform.startswith("linux"), "Linux fdinfo only")
    def test_kernel_flock_duplicate_then_unlock(self):
        with tempfile.TemporaryFile() as source:
            fcntl.flock(source, fcntl.LOCK_EX | fcntl.LOCK_NB)
            duplicate = os.dup(source.fileno())
            try:
                identity = os.fstat(duplicate)
                info = pathlib.Path(f"/proc/self/fdinfo/{duplicate}").read_text(
                    encoding="ascii")
                for module in (guardian, watchdog):
                    self.assertTrue(module._exclusive_flock_fdinfo(info, identity))
                fcntl.flock(source, fcntl.LOCK_UN)
                unlocked = pathlib.Path(f"/proc/self/fdinfo/{duplicate}").read_text(
                    encoding="ascii")
                for module in (guardian, watchdog):
                    self.assertFalse(module._exclusive_flock_fdinfo(unlocked, identity))
            finally:
                os.close(duplicate)


class VerifiedModuleConcurrencyTests(unittest.TestCase):
    """Protected source reads must never expose an uninitialized module."""

    def setUp(self):
        spec = importlib.util.spec_from_file_location(
            "aegis_auto_guardian_loader_fixture", SOURCE)
        self.loader = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.loader)
        self.witness_raw = SOURCE.with_name(
            "aegis_auto_native_witness.py").read_bytes()
        self.policy_raw = SOURCE.with_name(
            "aegis_auto_guard_policy.py").read_bytes()
        self.capture_raw = SOURCE.with_name(
            "aegis_auto_capture.py").read_bytes()
        self.endpoint_raw = SOURCE.with_name(
            "aegis_auto_endpoint.py").read_bytes()
        self.foreign_raw=SOURCE.with_name("aegis_auto_foreign_policy.py").read_bytes()
        self.raw = {self.loader.FOREIGN_SOURCE:self.foreign_raw,
                    self.loader.WITNESS: self.witness_raw,
                    self.loader.POLICY_SOURCE: self.policy_raw,
                    self.loader.CAPTURE_SOURCE: self.capture_raw,
                    self.loader.ENDPOINT_SOURCE: self.endpoint_raw}
        self.installed = {
            "foreign_policy_source_sha256":self.loader.digest(self.foreign_raw),
            "witness_sha256": self.loader.digest(self.witness_raw),
            "guard_policy_source_sha256": self.loader.digest(self.policy_raw),
            "capture_sha256": self.loader.digest(self.capture_raw),
            "endpoint_sha256": self.loader.digest(self.endpoint_raw)}
        self.names = ("aegis_auto_foreign_policy", "aegis_auto_native_witness", "aegis_auto_guard_policy",
                      "aegis_auto_capture", "aegis_auto_endpoint")
        self.previous = {name: sys.modules.get(name) for name in self.names}
        self.previous_cache = dict(self.loader._VERIFIED_MODULES)
        self.addCleanup(self._restore_modules)
        for name in self.names:
            sys.modules.pop(name, None)
        self.loader._VERIFIED_MODULES.clear()
        record = patch.object(self.loader, "record",
                              side_effect=lambda path: self.installed)
        regular = patch.object(self.loader, "regular",
                               side_effect=lambda path, *_args, **_kwargs:
                               self.raw[path])
        record.start()
        regular.start()
        self.addCleanup(record.stop)
        self.addCleanup(regular.stop)

    def _restore_modules(self):
        self.loader._VERIFIED_MODULES.clear()
        self.loader._VERIFIED_MODULES.update(self.previous_cache)
        for name, prior in self.previous.items():
            if prior is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = prior

    def load_witness(self):
        return self.loader.verified_module(
            self.loader.WITNESS, "aegis_auto_native_witness")

    def test_pristine_parent_loads_verified_dependencies_without_import_path(self):
        before = tuple(sys.path)
        endpoint = self.loader.verified_module(
            self.loader.ENDPOINT_SOURCE, "aegis_auto_endpoint")
        self.assertIs(endpoint.capture, sys.modules["aegis_auto_capture"])
        policy = self.loader.verified_module(
            self.loader.POLICY_SOURCE, "aegis_auto_guard_policy")
        self.assertIs(policy.policy_projection,
                      sys.modules["aegis_auto_native_witness"].policy_projection)
        self.assertEqual(tuple(sys.path), before)

    def test_cached_parent_rechecks_dependency_bytes_and_identity(self):
        endpoint = self.loader.verified_module(
            self.loader.ENDPOINT_SOURCE, "aegis_auto_endpoint")
        capture = sys.modules["aegis_auto_capture"]
        self.raw[self.loader.CAPTURE_SOURCE] = self.capture_raw + b"\n"
        with self.assertRaises(self.loader.Refused):
            self.loader.verified_module(self.loader.ENDPOINT_SOURCE,
                                        "aegis_auto_endpoint")
        self.raw[self.loader.CAPTURE_SOURCE] = self.capture_raw
        sys.modules["aegis_auto_capture"] = ModuleType("aegis_auto_capture")
        with self.assertRaises(self.loader.Refused):
            self.loader.verified_module(self.loader.ENDPOINT_SOURCE,
                                        "aegis_auto_endpoint")
        self.assertIs(sys.modules["aegis_auto_endpoint"], endpoint)
        sys.modules["aegis_auto_capture"] = capture
        self.assertIs(self.loader.verified_module(
            self.loader.ENDPOINT_SOURCE, "aegis_auto_endpoint"), endpoint)

    def test_policy_refuses_foreign_dependency_before_parent_execution(self):
        foreign = ModuleType("aegis_auto_native_witness")
        sys.modules["aegis_auto_native_witness"] = foreign
        with self.assertRaises(self.loader.Refused):
            self.loader.verified_module(self.loader.POLICY_SOURCE,
                                        "aegis_auto_guard_policy")
        self.assertNotIn("aegis_auto_guard_policy", sys.modules)
        self.assertIs(sys.modules["aegis_auto_native_witness"], foreign)

    def test_receipt_change_during_dependency_load_refuses_parent(self):
        initial = dict(self.installed)
        changed = {**initial, "generation_marker": "different"}
        reads = iter((initial, initial, changed))
        with patch.object(self.loader, "record", side_effect=lambda _path:
                          next(reads)):
            with self.assertRaises(self.loader.Refused):
                self.loader.verified_module(self.loader.ENDPOINT_SOURCE,
                                            "aegis_auto_endpoint")
        self.assertNotIn("aegis_auto_endpoint", sys.modules)
        self.assertIn("aegis_auto_capture", sys.modules)

    def test_failed_parent_initialization_removes_only_parent(self):
        original_compile = compile

        def fail_endpoint(raw, path, mode, **kwargs):
            if path == str(self.loader.ENDPOINT_SOURCE):
                raise RuntimeError("source-owned fixture compile refusal")
            return original_compile(raw, path, mode, **kwargs)

        with patch.object(self.loader, "compile", fail_endpoint, create=True):
            with self.assertRaises(RuntimeError):
                self.loader.verified_module(self.loader.ENDPOINT_SOURCE,
                                            "aegis_auto_endpoint")
        self.assertNotIn("aegis_auto_endpoint", sys.modules)
        self.assertNotIn("aegis_auto_endpoint", self.loader._VERIFIED_MODULES)
        self.assertIs(sys.modules["aegis_auto_capture"],
                      self.loader.verified_module(
                          self.loader.CAPTURE_SOURCE, "aegis_auto_capture"))

    def test_first_parent_load_waits_for_verified_dependency(self):
        entered = threading.Event()
        release = threading.Event()
        outcomes = {}
        original_compile = compile

        def compile_with_barrier(raw, path, mode, **kwargs):
            if path == str(self.loader.CAPTURE_SOURCE) and not entered.is_set():
                entered.set()
                if not release.wait(2):
                    raise RuntimeError("bounded fixture barrier expired")
            return original_compile(raw, path, mode, **kwargs)

        def load(label):
            try:
                outcomes[label] = self.loader.verified_module(
                    self.loader.ENDPOINT_SOURCE, "aegis_auto_endpoint")
            except BaseException as error:
                outcomes[label] = error

        with patch.object(self.loader, "compile", compile_with_barrier,
                          create=True):
            first = threading.Thread(target=load, args=("first",))
            second = threading.Thread(target=load, args=("second",))
            first.start()
            try:
                self.assertTrue(entered.wait(1))
                second.start()
                second.join(0.05)
                self.assertTrue(second.is_alive())
            finally:
                release.set()
                first.join(3)
                if second.ident is not None:
                    second.join(3)
        self.assertFalse(first.is_alive())
        self.assertFalse(second.is_alive())
        self.assertIsInstance(outcomes.get("first"), ModuleType)
        self.assertIs(outcomes.get("first"), outcomes.get("second"))

    def test_partial_publication_cannot_break_dependent_policy_import(self):
        first = self.load_witness()
        self.assertTrue(hasattr(first, "policy_projection"))
        published = threading.Event()
        release = threading.Event()
        outcomes = {}
        original_compile = compile

        def compile_with_barrier(raw, path, mode, **kwargs):
            if (threading.current_thread().name == "reload_witness" and
                    path == str(self.loader.WITNESS)):
                # Old verified_module publishes a fresh empty sys.modules
                # entry immediately before this call. No source bytes change.
                published.set()
                if not release.wait(2):
                    raise RuntimeError("bounded fixture barrier expired")
            return original_compile(raw, path, mode, **kwargs)

        def run(label, path, name):
            try:
                outcomes[label] = self.loader.verified_module(path, name)
            except BaseException as error:
                outcomes[label] = error

        with patch.object(self.loader, "compile", compile_with_barrier,
                          create=True):
            reloader = threading.Thread(
                target=run,
                args=("reload", self.loader.WITNESS,
                      "aegis_auto_native_witness"),
                name="reload_witness")
            reloader.start()
            # Either the fixed cache returns immediately or an implementation
            # reloads while holding its loader lock. In the old code this event
            # proves that a partially initialized module is globally visible.
            published.wait(0.2)
            policy = threading.Thread(
                target=run,
                args=("policy", self.loader.POLICY_SOURCE,
                      "aegis_auto_guard_policy"),
                name="load_policy")
            policy.start()
            try:
                # Give the dependent import a bounded chance to observe the
                # old partial module before allowing the reload to finish.
                policy.join(0.05)
            finally:
                release.set()
                reloader.join(3)
                policy.join(3)
        self.assertFalse(reloader.is_alive())
        self.assertFalse(policy.is_alive())
        self.assertIs(outcomes.get("reload"), first)
        self.assertIsInstance(outcomes.get("policy"), ModuleType)
        self.assertTrue(hasattr(outcomes["policy"], "verify_expected_policy"))

    def test_same_generation_returns_one_module_but_rechecks_source_bytes(self):
        first = self.load_witness()
        self.assertIs(self.load_witness(), first)
        self.assertIs(sys.modules["aegis_auto_native_witness"], first)
        self.raw[self.loader.WITNESS] = self.witness_raw + b"\n"
        with self.assertRaises(self.loader.Refused):
            self.load_witness()
        self.assertIs(sys.modules["aegis_auto_native_witness"], first)

    def test_live_generation_change_and_foreign_module_are_refused(self):
        first = self.load_witness()
        foreign = ModuleType("aegis_auto_native_witness")
        sys.modules["aegis_auto_native_witness"] = foreign
        with self.assertRaises(self.loader.Refused):
            self.load_witness()
        self.assertIs(sys.modules["aegis_auto_native_witness"], foreign)
        sys.modules["aegis_auto_native_witness"] = first
        changed = self.witness_raw + b"\n"
        self.raw[self.loader.WITNESS] = changed
        self.installed["witness_sha256"] = self.loader.digest(changed)
        with self.assertRaises(self.loader.Refused):
            self.load_witness()
        self.assertIs(sys.modules["aegis_auto_native_witness"], first)

    def test_foreign_preexisting_module_is_refused_before_first_load(self):
        foreign = ModuleType("aegis_auto_native_witness")
        sys.modules["aegis_auto_native_witness"] = foreign
        with self.assertRaises(self.loader.Refused):
            self.load_witness()
        self.assertIs(sys.modules["aegis_auto_native_witness"], foreign)

    def test_failed_initialization_leaves_no_cached_module(self):
        original_compile = compile
        failed = False

        def fail_once(raw, path, mode, **kwargs):
            nonlocal failed
            if path == str(self.loader.WITNESS) and not failed:
                failed = True
                raise RuntimeError("source-owned fixture compile refusal")
            return original_compile(raw, path, mode, **kwargs)

        with patch.object(self.loader, "compile", fail_once, create=True):
            with self.assertRaises(RuntimeError):
                self.load_witness()
            self.assertNotIn("aegis_auto_native_witness", sys.modules)
            loaded = self.load_witness()
        self.assertIs(sys.modules["aegis_auto_native_witness"], loaded)


class WatchdogVerifiedGuardianCacheTests(unittest.TestCase):
    def test_semantic_then_scoped_retire_and_reboot_reuse_one_generation(self):
        raw = b"""\
CALLS = 0
POLICY_SOURCE = 'source-owned-policy'
def own_source():
    global CALLS
    CALLS += 1
def _semantic_policy_readback():
    return None, {'deny': True}
def _no_client_grant(_projection):
    return True
def digest(_projection):
    return 'a' * 64
class Intent:
    def exists(self):
        return False
class Redirect:
    SCOPED_INTENT = Intent()
def verified_module(_path, _name):
    return Redirect()
"""
        expected = watchdog._sha(raw)
        with patch.object(watchdog, "_GUARDIAN_MODULE", None), \
             patch.object(watchdog, "_own_source",
                          return_value={"guardian_sha256": expected}), \
             patch.object(watchdog, "_read_root", return_value=raw):
            first = watchdog._guardian_module()
            self.assertEqual(watchdog._semantic_blocked(), "a" * 64)
            watchdog._retire_scoped_after_stop({}, "a" * 64)
            watchdog._retire_scoped_after_stop({}, "a" * 64, reboot=True)
            self.assertIs(watchdog._guardian_module(), first)
            self.assertEqual(first.CALLS, 5)
            with patch.object(watchdog, "_read_root", return_value=raw + b"\n"):
                with self.assertRaises(watchdog.Refused):
                    watchdog._guardian_module()
            self.assertIs(watchdog._guardian_module(), first)


class StopPolicyNamespaceTests(unittest.TestCase):
    def test_stop_derives_live_host_namespace_without_client_field(self):
        unit = "aegis-auto@" + "a" * 64 + ".service"
        boot = "11111111-2222-3333-4444-555555555555"
        request = {"schema": "aegis_auto_guardian_stop_v1",
                   "command": "STOP_BEGIN", "boot_id": boot,
                   "invocation_id": "c" * 32, "unit": unit}
        state = b"uplink=eth0\nschema=aegis_device_guard_v2\narmed=1\n"
        projection = b'[{"table":{"family":"inet","name":"aegis_device_guard"}}]'
        policy = {"schema": "aegis_auto_guardian_policy_v1",
                  "boot_id": boot, "netns_ino": 44,
                  "guard_dev": 1, "guard_ino": 2,
                  "state_sha256": guardian.digest(state),
                  "policy_sha256": guardian.digest(projection)}
        installed = {"guard_unit_sha256": "d" * 64,
                     "installation_anchor": "anchor"}
        witness = SimpleNamespace(snapshot_policy=lambda _path:
                                  (projection, None, None),
                                  assess_foreign_policy=lambda *_args,**_kw: {})
        original_stat = os.stat

        def stat_with_host_netns(path, *args, **kwargs):
            if path == "/proc/self/ns/net":
                return SimpleNamespace(st_ino=44)
            return original_stat(path, *args, **kwargs)

        def protected_record(path):
            if path == guardian.INSTALL:
                return installed
            if path == guardian.POLICY:
                return policy
            raise AssertionError("unexpected protected record")

        with tempfile.TemporaryDirectory() as directory:
            intent = pathlib.Path(directory) / "stop-intent.json"
            intent.write_bytes(b"{}")
            peer = Mock()
            with ExitStack() as stack:
                stack.enter_context(patch.object(pathlib.Path, "read_text",
                                                 return_value=boot + "\n"))
                stack.enter_context(patch.object(
                    guardian, "GUARD_HELPER", pathlib.Path(__file__)))
                stack.enter_context(patch.object(guardian, "STOP_INTENT", intent))
                stack.enter_context(patch.object(
                    guardian, "INSTALL", pathlib.Path(directory) / "install.json"))
                stack.enter_context(patch.object(guardian, "_stop_peer"))
                stack.enter_context(patch.object(
                    guardian, "_held_lock", return_value=(1, 2)))
                stack.enter_context(patch.object(guardian, "_private_stop_intent"))
                stack.enter_context(patch.object(guardian, "_run_helper_in_cgroup"))
                stack.enter_context(patch.object(
                    guardian, "record", side_effect=protected_record))
                stack.enter_context(patch.object(
                    guardian, "regular", return_value=state))
                stack.enter_context(patch.object(
                    guardian, "installation_anchor", return_value="anchor"))
                stack.enter_context(patch.object(
                    guardian, "_semantic_policy_readback",
                    return_value=(state, projection)))
                # This test isolates STOP_BEGIN's host namespace authority.
                # The guarded snapshot's full nft/canonical proof has its own
                # tests; keep its result exact while the fake witness supplies
                # only the namespace fixture's projection.
                stack.enter_context(patch.object(
                    guardian, "_semantic_policy_snapshot",
                    return_value=(projection, None, None)))
                stack.enter_context(patch.object(
                    guardian, "verified_module", return_value=witness))
                stack.enter_context(patch.object(
                    guardian, "_no_client_grant", return_value=True))
                phase = stack.enter_context(patch.object(
                    guardian, "_replace_stop_phase"))
                stack.enter_context(patch.object(
                    guardian, "_pid_alive", return_value=True))
                stack.enter_context(patch.object(
                    guardian.os, "stat", side_effect=stat_with_host_netns))
                anchor = stack.enter_context(patch.object(
                    guardian, "host_anchor", return_value={"netns_ino": 44}))
                checked = stack.enter_context(patch.object(
                    guardian, "_policy", wraps=guardian._policy))
                guardian._stop_effect(peer, 42, 5, request, (), 9, None)
                checked.assert_called_once_with({**request, "netns_ino": 44},
                                                (1, 2))
                anchor.assert_called_once()
                phase.assert_called_once_with("deny_proven")
                peer.sendall.assert_called_once()

                phase.reset_mock()
                peer.sendall.reset_mock()
                drift = guardian.INSTALL.parent / "foreign-policy-drift.json"
                drift.write_bytes(b"{}")
                with self.assertRaisesRegex(guardian.Refused, "foreign_policy_drift"):
                    guardian._stop_effect(peer, 42, 5, request, (), 9, None)
                phase.assert_not_called()
                peer.sendall.assert_not_called()
                drift.unlink()
                with self.assertRaisesRegex(guardian.Refused,
                                            "invalid_stop_request"):
                    guardian._stop_effect(peer, 42, 5,
                                          {**request, "netns_ino": 44},
                                          (), 9, None)
                phase.assert_not_called()
                peer.sendall.assert_not_called()

                anchor.return_value = {"netns_ino": 45}
                with self.assertRaisesRegex(guardian.Refused,
                                            "protected_policy_not_admitted"):
                    guardian._stop_effect(peer, 42, 5, request, (), 9, None)
                phase.assert_not_called()
                peer.sendall.assert_not_called()

                anchor.side_effect = guardian.Refused(
                    "guardian_not_in_host_namespace")
                with self.assertRaisesRegex(guardian.Refused,
                                            "guardian_not_in_host_namespace"):
                    guardian._stop_effect(peer, 42, 5, request, (), 9, None)
                phase.assert_not_called()
                peer.sendall.assert_not_called()


class GuardianCaptureCleanupTests(unittest.TestCase):
    def _qa_inputs(self, *, failure=None, abort_failure=None,
                   retire_failure=None):
        lease = Mock()
        lease.facts = {"children": []}
        if abort_failure is not None:
            lease.abort.side_effect = abort_failure
        topology = SimpleNamespace(open_effect=Mock(return_value=lease))
        endpoint_actor = object()
        admitted = MagicMock()
        admitted.endpoint = endpoint_actor
        admitted.__enter__.return_value = admitted
        endpoint = SimpleNamespace(
            mint_endpoint_receipt=Mock(return_value=admitted),
            admit_endpoint=Mock(side_effect=AssertionError(
                "the minted lease is reused; no second by-path admission")),
            retire_endpoint_receipt=Mock(side_effect=retire_failure))
        proof = object()
        def capture_ready(**_kwargs):
            if failure is not None:
                raise failure
            return proof
        capture = SimpleNamespace(CaptureEchoEndpoint=type(endpoint_actor),
                                  capture_ready=capture_ready)
        original = {"mode": "full-wide-tun", "private_unit":
                    "aegis-auto@" + "a" * 64 + ".service",
                    "boot_id": "boot", "netns_ino": 12}
        effect = {"pid1_invocation_id": "b" * 32}
        owner = {"installed_generation_sha256": "c" * 64,
                 "installed_manifest_sha256": "d" * 64}
        current = {"policy_sha256": "e" * 64}
        return (lease, capture, endpoint, topology, original, effect,
                owner, current, proof)

    def test_failed_qa_proof_preserves_primary_and_never_closes(self):
        primary = guardian.Refused("actual_capture_primary")
        values = self._qa_inputs(failure=primary,
                                 abort_failure=OSError("secret abort"),
                                 retire_failure=OSError("secret retire"))
        lease, capture, endpoint, topology, original, effect, owner, current, _ = values
        with patch.object(guardian, "_capture_step") as diagnostic:
            with self.assertRaises(guardian.Refused) as caught:
                guardian._qa_capture_once(
                    capture=capture, endpoint=endpoint, topology=topology,
                    witness=SimpleNamespace(snapshot_policy=object()),
                    original=original, effect=effect, owner=owner,
                    current=current, output_drop_handle=3,
                    installed_main_sha256="f" * 64, main_pid=123)
        self.assertIs(caught.exception, primary)
        lease.abort.assert_called_once_with()
        lease.close.assert_not_called()
        endpoint.retire_endpoint_receipt.assert_called_once_with()
        steps = [call.args[0] for call in diagnostic.call_args_list]
        self.assertLess(steps.index("failure"), steps.index("cleanup_fault"))

    def test_successful_qa_proof_closes_once(self):
        values = self._qa_inputs()
        lease, capture, endpoint, topology, original, effect, owner, current, proof = values
        with patch.object(guardian, "_capture_step"):
            actual = guardian._qa_capture_once(
                capture=capture, endpoint=endpoint, topology=topology,
                witness=SimpleNamespace(snapshot_policy=object()),
                original=original, effect=effect, owner=owner,
                current=current, output_drop_handle=3,
                installed_main_sha256="f" * 64, main_pid=123)
        self.assertIs(actual, proof)
        lease.close.assert_called_once_with()
        lease.abort.assert_not_called()
        endpoint.retire_endpoint_receipt.assert_called_once_with()

    def test_successful_proof_without_close_ack_still_refuses(self):
        values = self._qa_inputs()
        lease, capture, endpoint, topology, original, effect, owner, current, _ = values
        close_failure = guardian.Refused("capture_effect_close_unconfirmed")
        lease.close.side_effect = close_failure
        with patch.object(guardian, "_capture_step"):
            with self.assertRaises(guardian.Refused) as caught:
                guardian._qa_capture_once(
                    capture=capture, endpoint=endpoint, topology=topology,
                    witness=SimpleNamespace(snapshot_policy=object()),
                    original=original, effect=effect, owner=owner,
                    current=current, output_drop_handle=3,
                    installed_main_sha256="f" * 64, main_pid=123)
        self.assertIs(caught.exception, close_failure)
        lease.abort.assert_not_called()
        endpoint.retire_endpoint_receipt.assert_called_once_with()

    def test_failed_redirect_effect_aborts_without_success_ack(self):
        lease = Mock()
        primary = guardian.Refused("original_probe_refusal")
        with patch.object(guardian, "_capture_step"):
            guardian._capture_finish_effect(lease, completed=False,
                                            primary=primary,
                                            mode="wide-redirect-safe",
                                            success_step="redirect_effect_closed")
        lease.abort.assert_called_once_with()
        lease.close.assert_not_called()

    def test_held_lease_close_failure_does_not_mask_capture_primary(self):
        lease = Mock()
        lease.close.side_effect = OSError("secret cleanup path")
        primary = guardian.Refused("actual_capture_primary")
        with patch.object(guardian, "_capture_step") as diagnostic:
            with self.assertRaises(guardian.Refused) as caught:
                with guardian._CaptureHeldLease(lease, "wide-redirect-safe"):
                    raise primary
        self.assertIs(caught.exception, primary)
        lease.revalidate.assert_called_once_with()
        lease.close.assert_called_once_with()
        diagnostic.assert_called_with("cleanup_fault",
                                      mode="wide-redirect-safe",
                                      error=lease.close.side_effect)

    def test_held_lease_revalidation_failure_keeps_original(self):
        lease = Mock()
        primary = guardian.Refused("admission_changed")
        lease.revalidate.side_effect = primary
        lease.close.side_effect = OSError("private cleanup")
        with patch.object(guardian, "_capture_step"):
            with self.assertRaises(guardian.Refused) as caught:
                with guardian._CaptureHeldLease(lease, "full-wide-tun"):
                    self.fail("effect entered after failed admission")
        self.assertIs(caught.exception, primary)
        lease.close.assert_called_once_with()

    def test_capture_diagnostic_omits_private_error_and_paths(self):
        output = io.StringIO()
        private_path = "/private/secret/credential-token"
        with patch.object(guardian, "_capture_process_diagnostic",
                          return_value={"pidfd_live": True,
                                        "host_netns": True,
                                        "unit_cgroup": True}), \
             patch.object(guardian.Path, "is_file", return_value=True), \
             redirect_stderr(output):
            guardian._capture_step("failure", mode="wide-redirect-safe",
                                   main_pid=123,
                                   unit="aegis-auto@" + "a" * 64 + ".service",
                                   children=[{"pid": 456,
                                              "receipt": private_path}],
                                   error=RuntimeError(private_path))
        line = output.getvalue()
        self.assertTrue(line.startswith("aegis_auto_capture_step "))
        self.assertLessEqual(len(line), 2080)
        self.assertNotIn(private_path, line)
        self.assertNotIn("credential", line)
        payload = json.loads(line.partition(" ")[2])
        self.assertEqual(payload["error_class"], "runtime_error")
        self.assertEqual(payload["children"][0]["receipt_present"], True)

    def test_capture_nft_diagnostic_retains_counters_without_private_policy(self):
        private = "/private/secret/credential-token"
        events = []
        class Listing:
            def __init__(self, args, **_kwargs):
                family, table = args[-2:]
                events.append(("spawn", table))
                chain = "prerouting" if family == "ip" else "output"
                rule = {"family": family, "table": table, "chain": chain,
                        "handle": 7, "comment": private,
                        "expr": [{"match": {"right": private}},
                                 {"counter": {"packets": 3, "bytes": 96}},
                                 {"accept": None}]}
                self.table, self.returncode = table, None
                self.stdout = json.dumps({"nftables": [{"rule": rule}]}).encode()
            def communicate(self, timeout=None):
                assert timeout == 0.5
                events.append(("reap", self.table))
                self.returncode = 0
                return self.stdout, b""
            def poll(self):
                return self.returncode
        output = io.StringIO()
        with patch.object(guardian.subprocess, "Popen", side_effect=Listing), \
             redirect_stderr(output):
            guardian._capture_nft_diagnostic("redirect_proof_failure")
        # Both inert listings start together and both finish before return.
        self.assertEqual([e[0] for e in events], ["spawn", "spawn", "reap", "reap"])
        lines = output.getvalue().splitlines()
        self.assertEqual(len(lines), 2)
        self.assertNotIn(private, output.getvalue())
        for line in lines:
            self.assertTrue(line.startswith("aegis_auto_capture_nft "))
            payload = json.loads(line.partition(" ")[2])
            self.assertEqual(payload["counters"][0]["packets"], 3)
            self.assertEqual(payload["counters"][0]["bytes"], 96)
            self.assertEqual(set(payload["counters"][0]),
                             {"chain", "handle", "packets", "bytes"})

    def test_capture_nft_diagnostic_never_replaces_primary_failure(self):
        output = io.StringIO()
        with patch.object(guardian.subprocess, "Popen",
                          side_effect=TimeoutError("private token")) as run, \
             redirect_stderr(output):
            guardian._capture_nft_diagnostic("redirect_proof_failure")
            self.assertEqual(run.call_count, 2)
            guardian._capture_nft_diagnostic("untrusted-private-label")
            self.assertEqual(run.call_count, 2)
        self.assertEqual(output.getvalue(), "")

    def test_stopped_policy_refuses_any_remaining_dnat_reply_grant(self):
        projection = [{"rule": {"chain": "output", "expr": [
            {"match": {"left": {"meta": {"key": "oifname"}},
                       "right": "scoped0", "op": "=="}},
            {"match": {"left": {"ct": {"key": "status"}},
                       "right": "dnat", "op": "in"}},
            {"accept": None}]}}]
        with patch.object(guardian.Path, "exists", return_value=False):
            self.assertFalse(guardian._no_client_grant(json.dumps(projection).encode()))
            self.assertTrue(guardian._no_client_grant(b"[]"))

    def test_capture_failure_retains_owner_channel_and_omits_private_reason(self):
        instance = guardian.Guardian()
        request = {"mode": "wide-redirect-safe", "private_unit":
                   "aegis-auto@" + "a" * 64 + ".service",
                   "transaction_nonce": "b" * 32}
        grant = {"nonce": "c" * 64, "policy_sha256": "d" * 64,
                 "native_receipt_sha256": "e" * 64}
        instance.active_request = request
        instance.active_grant = grant
        instance.active_lineage = None
        instance.active_capture = None
        effect = {"schema": "aegis_auto_guardian_effect_request_v1",
                  "command": "CAPTURE_READY", "guardian_nonce": grant["nonce"],
                  "mode": request["mode"], "private_unit": request["private_unit"],
                  "boot_id": "boot", "netns_ino": 42, "stage_dev": 7,
                  "stage_ino": 8, "policy_sha256": grant["policy_sha256"],
                  "native_receipt_sha256": grant["native_receipt_sha256"],
                  "pid1_job_id": 9,
                  "pid1_job_path": "/org/freedesktop/systemd1/job/9",
                  "pid1_unit": request["private_unit"],
                  "pid1_invocation_id": "f" * 32}
        watchdog = Mock()
        watchdog.revalidate.return_value = {"phase": "LATCHED"}
        secret = "/private/key/token"
        with patch.object(guardian, "_capture_effect",
                          side_effect=OSError(secret)):
            retained, reply, failed, latched = instance._capture_authorized_effect(
                effect, request, grant, 3, 4, {}, None, watchdog)
        self.assertTrue(failed)
        self.assertTrue(latched)
        self.assertIsNone(retained)
        self.assertIsNone(instance.active_capture)
        watchdog.latch.assert_called_once_with("f" * 32)
        self.assertEqual(reply["schema"], "aegis_auto_capture_refused_v1")
        self.assertEqual(reply["reason"], "os_error")
        self.assertEqual(reply["command"], "CAPTURE_READY")
        self.assertEqual(reply["pid1_job_id"], 9)
        self.assertNotIn(secret, json.dumps(reply))
        # The retained peer can still carry the authenticated inverse packet.
        left, right = socket.socketpair()
        try:
            left.sendall(json.dumps(reply).encode())
            self.assertEqual(json.loads(right.recv(4096)), reply)
            right.sendall(b"COMPENSATED_STOP")
            self.assertEqual(left.recv(4096), b"COMPENSATED_STOP")
        finally:
            left.close()
            right.close()

    def test_capture_revalidation_failure_preserves_prior_proof(self):
        instance = guardian.Guardian()
        request = {"mode": "full-wide-tun", "private_unit":
                   "aegis-auto@" + "a" * 64 + ".service",
                   "transaction_nonce": "b" * 32}
        grant = {"nonce": "c" * 64, "policy_sha256": "d" * 64,
                 "native_receipt_sha256": "e" * 64}
        instance.active_request = request
        instance.active_grant = grant
        instance.active_lineage = None
        prior = {"sha256": "f" * 64}
        instance.active_capture = {"sha256": prior["sha256"]}
        effect = {"command": "CAPTURE_REVALIDATE", "guardian_nonce": grant["nonce"],
                  "mode": request["mode"], "boot_id": "boot", "netns_ino": 42,
                  "stage_dev": 7, "stage_ino": 8,
                  "policy_sha256": grant["policy_sha256"],
                  "native_receipt_sha256": grant["native_receipt_sha256"],
                  "pid1_job_id": 9,
                  "pid1_job_path": "/org/freedesktop/systemd1/job/9",
                  "pid1_unit": request["private_unit"],
                  "pid1_invocation_id": "1" * 32}
        watchdog = Mock()
        watchdog.revalidate.return_value = {"phase": "LOST"}
        retained, reply, failed, latched = instance._capture_authorized_effect(
            effect, request, grant, 3, 4, {}, prior, watchdog)
        self.assertTrue(failed)
        self.assertTrue(latched)
        self.assertIs(retained, prior)
        self.assertEqual(instance.active_capture["sha256"], prior["sha256"])
        watchdog.latch.assert_not_called()
        self.assertEqual(reply["command"], "CAPTURE_REVALIDATE")
        self.assertEqual(reply["reason"], "refused")

    def test_capture_refusal_requires_original_owner_and_watchdog(self):
        request = {"private_unit": "aegis-auto@" + "a" * 64 + ".service"}
        with patch.object(guardian, "_held_guard", return_value=(1, 2)), \
             patch.object(guardian, "_held_install", return_value=True), \
             patch.object(guardian, "_pid_alive", return_value=True), \
             patch.object(guardian, "_stage", return_value=(3, 4)) as stage:
            actor = Mock()
            actor.revalidate.return_value = {"phase": "REGISTERED"}
            guardian._capture_refusal_owner_held(
                request, 5, (1, 2), 6, 7, (3, 4), 8, actor,
                allow_registered=True)
            stage.assert_called_with(7, request, initial=False)
            with self.assertRaises(guardian.Refused):
                guardian._capture_refusal_owner_held(
                    request, 5, (1, 2), 6, 7, (3, 4), 8, actor,
                    allow_registered=False)
            actor.revalidate.return_value = {"phase": "LOST"}
            with self.assertRaises(guardian.Refused):
                guardian._capture_refusal_owner_held(
                    request, 5, (1, 2), 6, 7, (3, 4), 8, actor,
                    allow_registered=True)
            stage.return_value = (3, 5)
            actor.revalidate.return_value = {"phase": "LATCHED"}
            with self.assertRaises(guardian.Refused):
                guardian._capture_refusal_owner_held(
                    request, 5, (1, 2), 6, 7, (3, 4), 8, actor,
                    allow_registered=False)

    def test_capture_refusal_does_not_admit_malformed_job_identity(self):
        original = {"private_unit": "aegis-auto@" + "a" * 64 + ".service"}
        effect = {"schema": "aegis_auto_guardian_effect_request_v1",
                  "command": "CAPTURE_READY", "guardian_nonce": "b" * 64,
                  "mode": "full-wide-tun", "private_unit": original["private_unit"],
                  "boot_id": "boot", "netns_ino": 42,
                  "stage_dev": 7, "stage_ino": 8,
                  "policy_sha256": "c" * 64,
                  "native_receipt_sha256": "d" * 64,
                  "pid1_job_id": 9, "pid1_job_path": "/foreign/job/9",
                  "pid1_unit": original["private_unit"],
                  "pid1_invocation_id": "e" * 32}
        with self.assertRaises(guardian.Refused):
            guardian._capture_request_shape(effect, original)

    def test_precommit_main_stop_requires_latched_owner_and_exact_deny_intent(self):
        journal = {"phase": "LATCHED", "guard_dev": 7, "guard_ino": 8,
                   "invocation_id": "a" * 32,
                   "private_unit": "aegis-auto@" + "b" * 64 + ".service",
                   "boot_id": "boot"}
        with patch.object(watchdog, "_alive", return_value=True), \
             patch.object(watchdog, "_guard_identity", return_value=(7, 8)), \
             patch.object(watchdog, "_normal_stop_intent", return_value=True) as intent:
            self.assertTrue(watchdog._expected_main_stop(
                journal, committed=False, worker_pidfd=3,
                guardian_pidfd=4, guard_fd=5))
            intent.assert_called_once_with(journal)
            intent.return_value = False
            self.assertFalse(watchdog._expected_main_stop(
                journal, committed=False, worker_pidfd=3,
                guardian_pidfd=4, guard_fd=5))
            intent.reset_mock()
            journal["phase"] = "REGISTERED"
            self.assertFalse(watchdog._expected_main_stop(
                journal, committed=False, worker_pidfd=3,
                guardian_pidfd=4, guard_fd=5))
            intent.assert_not_called()

    def test_precommit_stop_intent_is_exact_and_stays_on_same_inverse_lease(self):
        journal = {"phase": "LATCHED", "guard_dev": 7, "guard_ino": 8,
                   "invocation_id": "a" * 32,
                   "private_unit": "aegis-auto@" + "b" * 64 + ".service",
                   "boot_id": "boot"}
        intent = {"schema": "aegis_auto_stop_intent_v1", "boot_id": "boot",
                  "service": journal["private_unit"],
                  "invocation_id": journal["invocation_id"],
                  "phase": "deny_proven"}
        with tempfile.TemporaryDirectory() as path:
            location = pathlib.Path(path) / "auto-stop-intent.json"
            location.write_text(json.dumps(intent), encoding="ascii")
            with patch.object(watchdog, "STOP_INTENT", location), \
                 patch.object(watchdog, "_read_root",
                              side_effect=lambda _path: location.read_bytes()), \
                 patch.object(watchdog, "_semantic_blocked",
                              return_value="c" * 64), \
                 patch.object(watchdog, "_alive", return_value=True), \
                 patch.object(watchdog, "_guard_identity", return_value=(7, 8)):
                self.assertTrue(watchdog._expected_main_stop(
                    journal, committed=False, worker_pidfd=3,
                    guardian_pidfd=4, guard_fd=5))
                intent["invocation_id"] = "d" * 32
                location.write_text(json.dumps(intent), encoding="ascii")
                with self.assertRaises(watchdog.Refused):
                    watchdog._expected_main_stop(
                        journal, committed=False, worker_pidfd=3,
                        guardian_pidfd=4, guard_fd=5)
                intent["invocation_id"] = journal["invocation_id"]
                intent["phase"] = "pending"
                location.write_text(json.dumps(intent), encoding="ascii")
                self.assertFalse(watchdog._expected_main_stop(
                    journal, committed=False, worker_pidfd=3,
                    guardian_pidfd=4, guard_fd=5))

    def test_precommit_main_pidfd_event_only_enters_stopping_for_owned_inverse(self):
        journal = {"phase": "LATCHED", "guard_dev": 7, "guard_ino": 8,
                   "invocation_id": "a" * 32,
                   "private_unit": "aegis-auto@" + "b" * 64 + ".service",
                   "boot_id": "boot"}
        watcher = Mock()
        with patch.object(watchdog, "_alive", return_value=True) as alive, \
             patch.object(watchdog, "_guard_identity", return_value=(7, 8)), \
             patch.object(watchdog, "_normal_stop_intent", return_value=True) as intent:
            self.assertTrue(watchdog._main_exit_stopping(
                9, 9, watcher, journal, committed=False,
                worker_pidfd=3, guardian_pidfd=4, guard_fd=5))
            watcher.unregister.assert_called_once_with(9)
            watcher.reset_mock()
            self.assertFalse(watchdog._main_exit_stopping(
                10, 9, watcher, journal, committed=False,
                worker_pidfd=3, guardian_pidfd=4, guard_fd=5))
            watcher.unregister.assert_not_called()
            alive.return_value = False
            self.assertFalse(watchdog._main_exit_stopping(
                9, 9, watcher, journal, committed=False,
                worker_pidfd=3, guardian_pidfd=4, guard_fd=5))
            watcher.unregister.assert_not_called()
            intent.return_value = False
            alive.return_value = True
            self.assertFalse(watchdog._main_exit_stopping(
                9, 9, watcher, journal, committed=False,
                worker_pidfd=3, guardian_pidfd=4, guard_fd=5))
            watcher.unregister.assert_not_called()
            journal["phase"] = "LATCHED"
        with patch.object(watchdog, "_alive", return_value=True), \
             patch.object(watchdog, "_guard_identity", return_value=(7, 9)), \
             patch.object(watchdog, "_normal_stop_intent") as intent:
            self.assertFalse(watchdog._expected_main_stop(
                journal, committed=False, worker_pidfd=3,
                guardian_pidfd=4, guard_fd=5))
            intent.assert_not_called()


class WatchdogFinalizedCommitTests(unittest.TestCase):
    def test_finalized_commit_binds_original_guard_and_live_post_capture_policy(self):
        unit = "aegis-auto@" + "a" * 64 + ".service"
        original = watchdog._sha(b"original-deny-policy")
        post_capture = watchdog._sha(b"active-capture-policy")
        capture = watchdog._sha(b"native-capture-proof")
        invocation = "b" * 32
        with tempfile.TemporaryDirectory() as directory:
            stage_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
            try:
                stage = SimpleNamespace(st_mode=stat.S_IFDIR | 0o700,
                                        st_uid=0, st_dev=17, st_ino=23)
                terminal = {"schema": 1, "outcome": "finalized",
                            "private_unit": unit, "stage": [17, 23],
                            "native_guard": {"policy_sha256": original},
                            "native_capture_sha256": capture}
                raw = json.dumps(terminal, sort_keys=True).encode()
                terminal_sha = watchdog._sha(raw)
                header = json.dumps({
                    "phase": "finalized",
                    "leaves": {"receipts/activation-owner/terminal.json":
                               terminal_sha}}).encode()
                module = SimpleNamespace(
                    _protected_stage_receipt=lambda _fd, _leaf: raw,
                    _protected_stage_receipt_for_header=lambda _fd: header,
                    unique=watchdog._unique,
                    _semantic_policy_readback=lambda: ({}, b"active-capture-policy"),
                    digest=watchdog._sha)
                with patch.object(watchdog, "_guardian_module", return_value=module), \
                     patch.object(watchdog.os, "fstat", return_value=stage), \
                     patch.object(watchdog, "_unit_facts",
                                  return_value={"InvocationID": invocation}):
                    self.assertNotEqual(original, post_capture)
                    self.assertEqual(watchdog._finalized_stage(
                        stage_fd, unit, terminal_sha, invocation, capture,
                        original, post_capture), post_capture)
                    for wrong in (("c" * 64, original, post_capture),
                                  (capture, "d" * 64, post_capture),
                                  (capture, original, "e" * 64)):
                        with self.subTest(wrong=wrong), \
                             self.assertRaises(watchdog.Refused):
                            watchdog._finalized_stage(
                                stage_fd, unit, terminal_sha, invocation,
                                *wrong)
            finally:
                os.close(stage_fd)

    def test_commit_wire_requires_exact_four_hashes(self):
        request = {"op": "COMMIT_ACTIVE", "terminal_sha256": "a" * 64,
                   "capture_sha256": "b" * 64,
                   "original_policy_sha256": "c" * 64,
                   "post_policy_sha256": "d" * 64}
        self.assertEqual(watchdog._commit_request_hashes(request),
                         ("a" * 64, "b" * 64, "c" * 64, "d" * 64))
        for altered in ({**request, "extra": "e" * 64},
                        {k: v for k, v in request.items()
                         if k != "capture_sha256"},
                        {**request, "post_policy_sha256": "F" * 64}):
            with self.subTest(altered=altered), \
                 self.assertRaises(watchdog.Refused):
                watchdog._commit_request_hashes(altered)

    def test_guardian_client_keeps_capture_and_policy_bindings_through_ack(self):
        client = watchdog.WatchdogClient(authority=Mock())
        request = {"op": "COMMIT_ACTIVE", "terminal_sha256": "a" * 64,
                   "capture_sha256": "b" * 64,
                   "original_policy_sha256": "c" * 64,
                   "post_policy_sha256": "d" * 64}
        reply = {"state": "COMMITTED_ACTIVE", "terminal_sha256": "a" * 64,
                 "private_main_pid": 123, "policy_sha256": "d" * 64,
                 "journal_sha256": watchdog._sha(b"durable-journal")}
        with patch.object(client, "_live"), \
             patch.object(watchdog, "_send") as send, \
             patch.object(watchdog, "_recv", return_value=reply), \
             patch.object(watchdog, "_read_root",
                          return_value=b"durable-journal"):
            self.assertEqual(client.commit_active(
                "a" * 64, capture_sha256="b" * 64,
                original_policy_sha256="c" * 64,
                post_policy_sha256="d" * 64), reply)
            send.assert_called_once_with(client.authority, request)
            with patch.object(watchdog, "_recv", return_value={
                    **reply, "policy_sha256": "c" * 64}), \
                 self.assertRaises(watchdog.Refused):
                client.commit_active(
                    "a" * 64, capture_sha256="b" * 64,
                    original_policy_sha256="c" * 64,
                    post_policy_sha256="d" * 64)

    def test_commit_diagnostic_omits_private_exception_details(self):
        secret = "private-invitation-and-key-material"
        self.assertEqual(watchdog._commit_refusal_diagnostic(
            "sealed_stage", watchdog.Refused(
                "watchdog_finalized_policy_or_unit_changed")),
            "aegis_auto_watchdog_commit_refused phase=sealed_stage "
            "class=refused reason=watchdog_finalized_policy_or_unit_changed")
        for error in (OSError(2, secret, "/private/path"),
                      watchdog.Refused(secret), ValueError(secret)):
            line = watchdog._commit_refusal_diagnostic(secret, error)
            self.assertNotIn(secret, line)
            self.assertNotIn("/private/path", line)
            self.assertIn("phase=unknown", line)
            self.assertIn("reason=other", line)


@unittest.skipUnless(sys.platform == "linux" and os.geteuid() == 0,
                     "requires the Linux root guard OFD contract")
class FirstGrantHandoffOrderTests(unittest.TestCase):
    def test_real_scm_rights_unlocked_handoff_then_held_carrier_gate(self):
        import array

        for variant in ("valid", "gate_refused", "unknown_command",
                        "stale_header"):
            with self.subTest(variant=variant), tempfile.TemporaryDirectory() as directory:
                root = pathlib.Path(directory)
                stage = root / "stage"
                stage.mkdir(mode=0o700)
                install = root / "install.lock"
                guard = root / "guard.lock"
                for leaf in (install, guard):
                    fd = os.open(leaf, os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600)
                    os.close(fd)
                nonce = "a" * 32
                generation = "b" * 64
                header = {"transaction_nonce": nonce,
                          "planned_generation": generation,
                          "phase": "metadata", "capture_started": False}
                header_raw = (json.dumps(header, sort_keys=True,
                                         separators=(",", ":")) + "\n").encode()
                header_leaf = stage / "header.json"
                header_leaf.write_bytes(header_raw)
                header_leaf.chmod(0o600)
                request = {"schema": "aegis_auto_guardian_request_v1",
                           "command": "prove_deny", "mode": "full-wide-tun",
                           "private_unit": "aegis-auto@" + generation + ".service",
                           "header_sha256": hashlib.sha256(header_raw).hexdigest(),
                           "transaction_nonce": nonce,
                           "planned_generation": generation,
                           "boot_id": "current-boot", "netns_ino": 1,
                           "actor_challenge": "c" * 64}
                if variant == "unknown_command":
                    request["command"] = "unknown"
                if variant == "stale_header":
                    request["header_sha256"] = "0" * 64
                stage_fd = os.open(stage, os.O_RDONLY | os.O_DIRECTORY)
                install_fd = os.open(install, os.O_RDWR)
                guard_fd = os.open(guard, os.O_RDWR)
                dummy_pidfd = os.open("/dev/null", os.O_RDONLY)
                fcntl.flock(install_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                client, server = socket.socketpair(socket.AF_UNIX,
                                                   socket.SOCK_SEQPACKET)
                events = []
                try:
                    payload = json.dumps(request, sort_keys=True,
                                         separators=(",", ":")).encode()
                    sent = client.sendmsg([payload], [
                        (socket.SOL_SOCKET, socket.SCM_RIGHTS,
                         array.array("i", (stage_fd, install_fd, guard_fd)))])
                    self.assertEqual(sent, len(payload))
                    # The receiver now owns the same initially unlocked guard
                    # OFD; the sender cannot keep an accidental lock alive.
                    os.close(stage_fd)
                    os.close(install_fd)
                    os.close(guard_fd)
                    stage_fd = install_fd = guard_fd = None
                    real_claim = guardian._claim_guard_handoff

                    def claim(fd):
                        value = real_claim(fd)
                        events.append("claim")
                        return value

                    def gate(_current, _source, _raw):
                        events.append("carrier_gate")
                        guardian._held_lock(receiver_guard[0], guard)
                        other = os.open(guard, os.O_RDWR | os.O_NOFOLLOW)
                        try:
                            with self.assertRaises(BlockingIOError):
                                fcntl.flock(other, fcntl.LOCK_EX | fcntl.LOCK_NB)
                        finally:
                            os.close(other)
                        if variant == "gate_refused":
                            raise guardian.Refused("typed_carrier_refusal")

                    transition = SimpleNamespace(
                        SOURCE_CONFIG=root / "source.json",
                        _source_facts=lambda: ({}, {}),
                        _cold_consumed_under_guard=gate,
                        read=lambda *_args: b"{}",
                        read_consumed_record=lambda *_args, **_kw: None,
                        historical_carriers_closed=lambda *_args: None)
                    receiver_guard = [None]
                    original_gate = guardian._currentboot_consumption_before_first_grant

                    def bound_gate(install_fd, received_guard_fd):
                        receiver_guard[0] = received_guard_fd
                        return original_gate(install_fd, received_guard_fd)

                    def stop_before_policy(*_args):
                        events.append("policy")
                        raise guardian.Refused("fixture_stops_before_grant")

                    with patch.object(guardian, "INSTALL_LOCK", install), \
                         patch.object(guardian, "GUARD_LOCK", guard), \
                         patch.object(guardian, "SPLIT", root / "split"), \
                         patch.object(guardian, "STOP_INTENT", root / "stop"), \
                         patch.object(guardian, "TERMINAL_MIGRATION_PENDING",
                                      root / "migration" / "pending.json"), \
                         patch.object(guardian, "record", return_value={
                             "worker_sha256": "d" * 64}), \
                         patch.object(guardian, "_unit_identity", return_value={
                             "InvocationID": "e" * 32}), \
                         patch.object(guardian, "_peer_identity",
                                      side_effect=lambda _peer:
                                      (os.getpid(), os.dup(dummy_pidfd))), \
                         patch.object(guardian, "_peer_executable"), \
                         patch.object(guardian, "verified_module",
                                      return_value=transition), \
                         patch.object(guardian, "host_anchor", return_value={
                             "boot_id": "current-boot"}), \
                         patch.object(guardian, "_claim_guard_handoff",
                                      side_effect=claim) as claimed, \
                         patch.object(guardian,
                                      "_currentboot_consumption_before_first_grant",
                                      side_effect=bound_gate), \
                         patch.object(guardian, "_policy",
                                      side_effect=stop_before_policy) as policy:
                        with self.assertRaises(guardian.Refused):
                            guardian.Guardian().serve_one(server)
                        if variant == "valid":
                            self.assertEqual(events,
                                             ["claim", "carrier_gate", "policy"])
                            claimed.assert_called_once()
                            policy.assert_called_once()
                        elif variant == "gate_refused":
                            self.assertEqual(events, ["claim", "carrier_gate"])
                            claimed.assert_called_once()
                            policy.assert_not_called()
                        else:
                            self.assertEqual(events, [])
                            claimed.assert_not_called()
                            policy.assert_not_called()
                    client.settimeout(0.2)
                    self.assertEqual(client.recv(4096), b"")
                    with os.fdopen(os.open(guard, os.O_RDWR | os.O_NOFOLLOW),
                                   "rb", closefd=True) as released:
                        fcntl.flock(released.fileno(),
                                    fcntl.LOCK_EX | fcntl.LOCK_NB)
                        fcntl.flock(released.fileno(), fcntl.LOCK_UN)
                finally:
                    client.close()
                    server.close()
                    os.close(dummy_pidfd)
                    for fd in (stage_fd, install_fd, guard_fd):
                        if fd is not None:
                            os.close(fd)


if __name__ == "__main__":
    unittest.main()
