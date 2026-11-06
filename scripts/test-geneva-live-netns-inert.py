#!/usr/bin/env python3
"""Actual harness functions under mocks; no unshare/privilege/network operation."""
import importlib.util
import json
import pathlib
import struct
import tempfile
import unittest
from unittest.mock import patch

spec=importlib.util.spec_from_file_location("geneva_native",pathlib.Path(__file__).with_name("test-geneva-live-netns.py"))
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)

class Contracts(unittest.TestCase):
    def test_fixture_checksums_and_wrap_inputs_are_real(self):
        packet=m.frame();self.assertEqual(m.checksum(packet[14:34]),0)
        pseudo=packet[26:34]+struct.pack("!BBH",0,6,len(packet)-34)+packet[34:]
        self.assertEqual(m.checksum(pseudo),0);self.assertEqual(packet[54:],b"abcdefghijklmnop")
    def test_guard_refuses_changed_source_before_ready_or_kill(self):
        with tempfile.TemporaryDirectory()as d:
            pathlib.Path(d,"watchdog-input.json").write_text(json.dumps({"tool_sha256":"wrong","child":{},"deadline":0}))
            with patch.object(m,"kill_owned")as kill,patch.object(m,"same_process",return_value=True):
                with self.assertRaises(RuntimeError):m.watchdog(d)
                kill.assert_not_called();self.assertFalse(pathlib.Path(d,"watchdog-ready.json").exists())
    def test_guard_refuses_reused_pid_before_ready_or_kill(self):
        with tempfile.TemporaryDirectory()as d:
            pathlib.Path(d,"watchdog-input.json").write_text(json.dumps({"tool_sha256":m.digest(m.SELF),"child":{},"deadline":0}))
            with patch.object(m,"kill_owned")as kill,patch.object(m,"same_process",return_value=False):
                with self.assertRaises(RuntimeError):m.watchdog(d)
                kill.assert_not_called();self.assertFalse(pathlib.Path(d,"watchdog-ready.json").exists())
    def test_kill_refuses_changed_process_identity(self):
        with patch.object(m,"same_process",return_value=False),patch.object(m.os,"killpg")as kill:
            m.kill_owned({"pid":123,"group":123});kill.assert_not_called()
    def test_guard_rejects_disarm_while_exact_child_live(self):
        with tempfile.TemporaryDirectory()as d:
            row={"pid":123,"group":123};pathlib.Path(d,"watchdog-input.json").write_text(json.dumps({"tool_sha256":m.digest(m.SELF),"child":row,"deadline":m.time.monotonic()+60}))
            pathlib.Path(d,"disarm.json").write_text("{}")
            with patch.object(m,"same_process",return_value=True),patch.object(m,"identity",return_value={"guard":True}),patch.object(m,"kill_owned")as kill:
                with self.assertRaises(RuntimeError):m.watchdog(d)
                kill.assert_not_called();self.assertFalse(pathlib.Path(d,"watchdog-terminal.json").exists())
    def test_command_failure_retains_actual_private_output(self):
        with tempfile.TemporaryDirectory()as d:
            result=m.subprocess.CompletedProcess(["fixture"],7,b"actualout",b"actualerr")
            with patch.object(m,"FAILURE_ROOT",pathlib.Path(d)),patch.object(m.subprocess,"run",return_value=result):
                with self.assertRaises(RuntimeError):m.command(["fixture","never-export-request"])
            path=next(pathlib.Path(d).glob("command-failure-*.json"));row=json.loads(path.read_text())
            self.assertEqual(bytes.fromhex(row["stderr_hex"]),b"actualerr");self.assertEqual(path.stat().st_mode&0o777,0o600)
            self.assertNotIn("never-export-request",path.read_text())
    def test_outer_retains_install_failure_without_launch(self):
        with tempfile.TemporaryDirectory()as d:
            binary=pathlib.Path(d,"binary").resolve();binary.write_bytes(b"public fixture");out=pathlib.Path(d,"attempt")
            with patch.object(m.sys,"platform","linux"),patch.object(m.os,"geteuid",return_value=0),patch.object(m.os,"readlink",return_value="namespace"),patch.object(m,"command",return_value=b"baseline"),patch.object(m,"prepare_installed",side_effect=RuntimeError("actual failure")),patch.object(m.subprocess,"Popen")as spawn,patch.object(m,"session_absent",return_value=True):
                with self.assertRaises(RuntimeError):m.outer(str(binary),str(out))
            spawn.assert_not_called();row=json.loads((out/"receipt.json").read_text())
            self.assertNotEqual(row["status"],"PASS_CONTROLLED_NATIVE_GENEVA");self.assertFalse(row["cleanup_checked"])
    def test_outer_bad_worker_source_stops_only_birth_bound_worker_and_retains_receipt(self):
        from unittest.mock import Mock
        with tempfile.TemporaryDirectory()as d:
            binary=pathlib.Path(d,"binary").resolve();binary.write_bytes(b"public fixture");out=pathlib.Path(d,"attempt")
            row={"pid":123,"start":"7","group":123,"argv":"aa","exe":"python"}
            child=Mock(pid=123);child.poll.return_value=None
            child.wait.side_effect=lambda timeout: child.poll.configure_mock(return_value=-9) or -9
            proof={"installed_sha256":m.digest(binary)}
            def spawn(*args,**kwargs):
                m.exclusive(out/"inner-start.json",{"child":row,"tool_sha256":"bad-source"});return child
            with patch.object(m.sys,"platform","linux"),patch.object(m.os,"geteuid",return_value=0),patch.object(m.os,"readlink",return_value="namespace"),patch.object(m,"command",return_value=b"baseline"),patch.object(m,"prepare_installed",return_value=(str(binary),proof)),patch.object(m,"identity",return_value=row),patch.object(m.subprocess,"Popen",side_effect=spawn),patch.object(m.os,"killpg")as kill,patch.object(m,"session_absent",return_value=True),patch.object(m,"cleanup_installed",return_value=True):
                with self.assertRaises(RuntimeError):m.outer(str(binary),str(out))
            kill.assert_called_once_with(123,m.signal.SIGKILL)
            receipt=json.loads((out/"receipt.json").read_text());self.assertTrue(receipt["cleanup_checked"]);self.assertNotEqual(receipt["status"],"PASS_CONTROLLED_NATIVE_GENEVA")
            self.assertFalse((out/"watchdog-input.json").exists())
    def test_export_never_copies_fixture_or_binary(self):
        with tempfile.TemporaryDirectory()as d:
            root=pathlib.Path(d,"stage");root.mkdir();out=pathlib.Path(d,"export")
            (root/"receipt.json").write_text('{"status":"FAIL"}');(root/"operator-fixture").mkdir();(root/"binary").write_bytes(b"not export")
            with patch.object(m.os,"geteuid",return_value=0):
                # Current process owns temporary fixtures; do not pretend native ownership.
                uid=(root/"receipt.json").stat().st_uid
                if uid==0:m.export_evidence(str(root),str(out))
                else:
                    with self.assertRaises(RuntimeError):m.export_evidence(str(root),str(out))
            self.assertFalse((out/"binary").exists());self.assertFalse((out/"operator-fixture").exists())
    def interrupted_outer(self, phase):
        from unittest.mock import Mock
        with tempfile.TemporaryDirectory()as d:
            binary=pathlib.Path(d,"binary").resolve();binary.write_bytes(b"public fixture");out=pathlib.Path(d,"attempt")
            row={"pid":123,"start":"7","group":123,"argv":"aa","exe":"python"};proof={"installed_sha256":m.digest(binary)}
            child=Mock(pid=123);child.poll.return_value=None
            waits=0
            def wait(timeout):
                nonlocal waits
                waits+=1
                if waits==1 and phase=="workerwait":raise KeyboardInterrupt()
                child.poll.return_value=0;return 0
            child.wait.side_effect=wait
            guard=Mock(pid=456,returncode=0);guard.poll.return_value=0
            if phase=="guardterminal":guard.communicate.side_effect=KeyboardInterrupt();guard.poll.return_value=None
            else:guard.communicate.return_value=(None,b"")
            spawns=0
            def spawn(*args,**kwargs):
                nonlocal spawns
                spawns+=1
                self.assertTrue(kwargs.get("start_new_session"))
                if spawns==1:
                    m.exclusive(out/"inner-start.json",{"child":row,"tool_sha256":m.digest(m.SELF)})
                    m.exclusive(out/"inner-result.json",{"scope":"mock only"})
                    return child
                return guard
            with patch.object(m.sys,"platform","linux"),patch.object(m.os,"geteuid",return_value=0),patch.object(m.os,"readlink",return_value="namespace"),patch.object(m,"command",return_value=b"baseline"),patch.object(m,"prepare_installed",return_value=(str(binary),proof)),patch.object(m,"identity",return_value=row),patch.object(m.subprocess,"Popen",side_effect=spawn),patch.object(m.os,"killpg"),patch.object(m,"session_absent",return_value=True),patch.object(m,"cleanup_installed",return_value=True):
                with self.assertRaises(RuntimeError):m.outer(str(binary),str(out))
            receipt=json.loads((out/"receipt.json").read_text());self.assertNotEqual(receipt["status"],"PASS_CONTROLLED_NATIVE_GENEVA")
            self.assertTrue(any(e["type"]=="KeyboardInterrupt"for e in receipt["errors"]))
            if phase=="guardterminal":self.assertTrue(receipt["watchdog_alive"]);self.assertFalse(receipt["installed_prefix_removed"])
            else:self.assertTrue(receipt["cleanup_checked"])
    def test_outer_worker_wait_interrupt_retains_checked_terminal_failure(self):self.interrupted_outer("workerwait")
    def test_outer_guard_terminal_interrupt_retains_live_guard_and_owned_files(self):self.interrupted_outer("guardterminal")

if __name__=="__main__":unittest.main()
