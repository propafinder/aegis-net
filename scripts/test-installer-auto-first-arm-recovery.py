#!/usr/bin/env python3
"""Inert filesystem controls for fresh AUTO first-arm publication.

Run as root in an isolated Linux environment. This never touches installed
AEGIS paths or starts a service. It exercises the production no-replace writer.
"""

import ast
import contextlib
import errno
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import types
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parent.parent
SOURCE = ROOT / "scripts/lib/aegis_installer_auto_v2.py"
INSTALLER = ROOT / "install.sh"


def embedded_python(marker):
    source = INSTALLER.read_text()
    begin = "<<'" + marker + "'\n"
    end = "\n" + marker + "\n"
    assert source.count(begin) == 1
    return source.split(begin, 1)[1].split(end, 1)[0]


def isolated_code(marker, paths, hooks):
    """Keep the production decision body; replace only external OS adapters."""
    class Isolate(ast.NodeTransformer):
        def visit_Constant(self, node):
            if isinstance(node.value, str) and node.value in paths:
                return ast.copy_location(ast.Constant(paths[node.value]), node)
            return node

        def visit_FunctionDef(self, node):
            if node.name in hooks:
                arguments = [ast.Name(arg.arg, ast.Load()) for arg in node.args.args]
                node.body = [ast.Return(ast.Call(ast.Name("_test_" + node.name,
                                                     ast.Load()), arguments, []))]
                return node
            return self.generic_visit(node)

        def visit_Call(self, node):
            node = self.generic_visit(node)
            if marker == "PY_AUTO_FIRST_ARM_STOP" and isinstance(node.func, ast.Attribute):
                name = (node.func.value.id if isinstance(node.func.value, ast.Name)
                        else None, node.func.attr)
                replacement = {("os", "pidfd_open"): "_test_pidfd",
                               ("select", "poll"): "_test_poll",
                               ("subprocess", "run"): "_test_run"}.get(name)
                if replacement:
                    node.func = ast.Name(replacement, ast.Load())
            return node

    tree = Isolate().visit(ast.parse(embedded_python(marker)))
    ast.fix_missing_locations(tree)
    return compile(tree, str(INSTALLER) + ":" + marker, "exec")


def load_source():
    spec = importlib.util.spec_from_file_location("aegis_first_arm_test", SOURCE)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@unittest.skipUnless(sys.platform == "linux" and os.geteuid() == 0,
                     "requires isolated root filesystem control")
class AtomicFirstArmPublication(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="aegis-first-arm-inert-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        self.addCleanup(os.close, self.fd)
        self.module = load_source()
        self.writer = self.module.atomic_exclusive_bytes

    def test_published_bytes_and_mode_are_exact_and_cannot_be_replaced(self):
        leaf = "device-guard.conf"
        original = b"schema=aegis_device_guard_v2\n"
        self.writer(self.fd, leaf, original, 0o600)
        path = self.root / leaf
        self.assertEqual(path.read_bytes(), original)
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        with self.assertRaises(OSError) as duplicate:
            self.writer(self.fd, leaf, b"foreign=1\n", 0o600)
        self.assertEqual(duplicate.exception.errno, errno.EEXIST)
        self.assertEqual(path.read_bytes(), original)

    def test_foreign_symlink_is_never_followed_or_replaced(self):
        protected = self.root / "protected"
        protected.write_bytes(b"unchanged")
        (self.root / "guard-unit").symlink_to(protected)
        with self.assertRaises(OSError) as duplicate:
            self.writer(self.fd, "guard-unit", b"unit\n", 0o644)
        self.assertEqual(duplicate.exception.errno, errno.EEXIST)
        self.assertEqual(protected.read_bytes(), b"unchanged")

    def test_interrupted_private_temp_does_not_publish_a_public_leaf(self):
        # The temporary name is deliberately not an accepted public leaf.
        partial = self.root / (".passive-tmp-" + "a" * 24)
        partial.write_bytes(b"partial")
        self.assertFalse((self.root / "guard-state").exists())
        self.writer(self.fd, "guard-state", b"deny=all\n", 0o600)
        self.assertEqual((self.root / "guard-state").read_bytes(), b"deny=all\n")
        self.assertEqual(partial.read_bytes(), b"partial")

    def test_short_write_keeps_public_name_absent_and_retry_publishes(self):
        original_write = os.write
        calls = 0

        def short_write(fd, data):
            nonlocal calls
            calls += 1
            return original_write(fd, data[:1]) if calls == 1 else 0

        with mock.patch.object(self.module.os, "write", short_write):
            with self.assertRaises(Exception):
                self.writer(self.fd, "guard-short", b"complete\n", 0o600)
        self.assertFalse((self.root / "guard-short").exists())
        self.writer(self.fd, "guard-short", b"complete\n", 0o600)
        self.assertEqual((self.root / "guard-short").read_bytes(), b"complete\n")

    def test_fsync_failure_keeps_public_name_absent_and_retry_publishes(self):
        with mock.patch.object(self.module.os, "fsync", side_effect=OSError(errno.EIO,
                                                                             "injected")):
            with self.assertRaises(OSError):
                self.writer(self.fd, "guard-fsync", b"complete\n", 0o600)
        self.assertFalse((self.root / "guard-fsync").exists())
        self.writer(self.fd, "guard-fsync", b"complete\n", 0o600)
        self.assertEqual((self.root / "guard-fsync").read_bytes(), b"complete\n")

    def test_rename_failure_keeps_public_name_absent_and_retry_publishes(self):
        class FailedRename:
            argtypes = None
            restype = None

            def __call__(self, *args):
                return -1

        fake_libc = types.SimpleNamespace(renameat2=FailedRename())
        with mock.patch.object(self.module.ctypes, "CDLL", return_value=fake_libc), \
             mock.patch.object(self.module.ctypes, "get_errno", return_value=errno.EIO):
            with self.assertRaises(OSError) as failure:
                self.writer(self.fd, "guard-rename", b"complete\n", 0o600)
        self.assertEqual(failure.exception.errno, errno.EIO)
        self.assertFalse((self.root / "guard-rename").exists())
        self.writer(self.fd, "guard-rename", b"complete\n", 0o600)
        self.assertEqual((self.root / "guard-rename").read_bytes(), b"complete\n")


@unittest.skipUnless(sys.platform == "linux" and os.geteuid() == 0,
                     "requires isolated Linux root filesystem control")
class FirstArmPhaseDecisions(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="aegis-first-arm-phases-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.control = self.root / "control"
        self.guard = self.root / "guard"
        self.etc = self.root / "etc"
        self.stage = self.control / "first-arm.ABCDEFGH"
        for directory in (self.control, self.guard, self.etc, self.stage):
            directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.candidate = self.root / "candidate"
        self.config = self.root / "config"
        self.installer = self.root / "installer"
        self.helper = self.root / "helpers/aegis-device-egress-guard.sh"
        for path, data, mode in ((self.candidate, b"client", 0o555),
                                 (self.config, b"[relay]\n", 0o600),
                                 (self.installer, b"installer", 0o555)):
            path.write_bytes(data)
            path.chmod(mode)
        (self.control / "fresh-passive-intent.json").write_bytes(b"passive\n")
        self.facts = {"source_config_sha256": self.sha(self.config.read_bytes()),
                      "relay_servers": ["192.0.2.1:443"]}
        (self.stage / "relay-facts.json").write_bytes(self.encode(self.facts))
        self.assessment = b"manager=systemd-networkd.service\ncapture_profile=wide-redirect-safe\n"
        (self.stage / "guard.conf").write_bytes(self.assessment)
        self.before = {"Id": "aegis-auto-guardian.service", "LoadState": "loaded",
                       "ActiveState": "active", "SubState": "running",
                       "MainPID": "1234", "ControlPID": "0",
                       "ControlGroup": "/system.slice/aegis-auto-guardian.service",
                       "InvocationID": "a" * 32, "NFileDescriptorStore": "0"}
        self.live = dict(self.before)
        self.guard_service = {"ActiveState": "active", "SubState": "exited",
                              "MainPID": "0"}
        self.manager_service = {"ActiveState": "active", "SubState": "running",
                                "MainPID": "3456"}
        self.tick = 1000
        self.missing_watchdog = False
        self.original = {"guard_unit_sha256": None,
                         "worker_sha256": self.sha(self.candidate.read_bytes())}
        self.install = self.guard / "INSTALL"
        self.install.write_bytes(self.encode(self.original))
        self.install.chmod(0o600)
        self.unit = self.etc / "aegis-device-egress-guard.service"
        self.state = self.guard / "device-guard.conf"
        self.policy = self.guard / "POLICY"
        self.receipt = self.guard / "auto-guard-first-arm.json"
        self.unit_bytes = b"[Unit]\nDescription=guard\n"
        self.projection = b"deny-policy"
        self.boot = "11111111-1111-1111-1111-111111111111"
        self.c = types.SimpleNamespace(
            CONTROL=self.control,
            bounded_root_bytes=lambda path, maximum, modes: Path(path).read_bytes(),
            strict_json=lambda raw: json.loads(raw),
            fresh_package_lock=lambda fd: None,
            control_directory=lambda: os.open(self.control, os.O_RDONLY | os.O_DIRECTORY),
            current_boot=lambda: self.boot,
            absolute=lambda value: Path(value).absolute(),
            directory=lambda path, mode=None: os.open(path, os.O_RDONLY | os.O_DIRECTORY),
            guardian_ready=lambda candidate, phase: phase,
            PHASE_TIMEOUT=30.0,
            passive_actor_status=self.retired_actor_status,
            call_output=lambda *args, **kwargs: b"manager=ready\n",
            control_leaf=load_source().control_leaf,
            _passive_write=load_source()._passive_write)
        self.g = types.SimpleNamespace(
            INSTALL=self.install, GUARD_UNIT_FILE=self.unit, POLICY=self.policy,
            EXPECTED_GUARD_UNIT=self.unit_bytes,
            own_source=lambda pending_guard_unit=False: None,
            _semantic_policy_readback=lambda deadline=None:
                (self.assessment, self.projection),
            record=lambda path: json.loads(Path(path).read_bytes()),
            _no_client_grant=lambda projection: True)
        self.c.installed_guardian = lambda: self.g
        self.code = isolated_code("PY_AUTO_FIRST_ARM_INTENT", {
            "/var/lib/aegis-install/client/device-guard.conf": str(self.state),
            "/etc/systemd/system": str(self.etc),
            "/usr/local/lib/aegis/helpers/aegis-device-egress-guard.sh": str(self.helper),
            "/sys/fs/cgroup": str(self.root / "cgroup")},
            ("load", "show", "birth", "no_client"))

    @staticmethod
    def sha(raw):
        return hashlib.sha256(raw).hexdigest()

    def retired_actor_status(self, deadline=None, retired_guardian_invocation=None):
        self.assertEqual(retired_guardian_invocation, self.before['InvocationID'])
        return ([object()] * (2 if self.missing_watchdog else 3),
                ['aegis-auto-guardian.service', 'aegis-auto-watchdog.service']
                if self.missing_watchdog else ['aegis-auto-guardian.service'])

    @staticmethod
    def encode(value):
        return json.dumps(value, sort_keys=True, separators=(",", ":")).encode() + b"\n"

    def proof(self, action, *extra):
        argv = ["proof", action, str(self.candidate), str(self.config),
                "wide-redirect-safe", str(self.root / "helpers"),
                str(self.installer), "9", *map(str, extra)]
        output = io.StringIO()
        env = {"_test_load": lambda name: {"aegis_installer_auto_v2": self.c,
                                            "aegis_auto_guardian": self.g}[name],
               "_test_show": lambda unit: dict(self.live if unit == "aegis-auto-guardian.service"
                                          else self.guard_service if unit == "aegis-device-egress-guard.service"
                                          else self.manager_service),
               "_test_birth": lambda pid: self.tick,
               "_test_no_client": lambda: None}
        with mock.patch.object(sys, "argv", argv), contextlib.redirect_stdout(output):
            exec(self.code, env)
        return output.getvalue().strip().split()[-1]

    def begin(self):
        self.assertEqual(self.proof("begin", self.stage), "live")

    def inactive(self):
        self.live = dict(self.before, ActiveState="inactive", SubState="dead",
                         MainPID="0", ControlGroup="")

    def stopped(self):
        self.inactive()
        self.tick = 1001
        self.assertEqual(self.proof("resume"), "stopped")

    def guarded(self):
        self.stopped()
        upgraded = dict(self.original, guard_unit_sha256=self.sha(self.unit_bytes))
        self.install.write_bytes(self.encode(upgraded))
        self.unit.write_bytes(self.unit_bytes)
        self.unit.chmod(0o644)
        hook = ("[Service]\nEnvironment=AEGIS_DEVICE_GUARD_STATE=" + str(self.state) +
                "\nExecStartPre=+/usr/bin/nsenter --mount=/proc/1/ns/mnt "
                "--root=/proc/1/root -- /bin/bash " + str(self.helper) + " bind-manager")
        hook += ("\nExecStartPost=+/usr/bin/nsenter --mount=/proc/1/ns/mnt "
                 "--root=/proc/1/root -- /bin/bash " + str(self.helper) +
                 " manager-ready\nTimeoutStartSec=90")
        self.dropin = self.etc / "systemd-networkd.service.d/30-aegis-device-guard.conf"
        self.dropin.parent.mkdir(mode=0o700)
        self.dropin.write_bytes(("[Unit]\nRequires=aegis-device-egress-guard.service\n"
                                 "After=aegis-device-egress-guard.service\n" + hook + "\n").encode())
        self.dropin.chmod(0o644)
        self.state.write_bytes(self.assessment)
        self.state.chmod(0o600)
        self.policy.write_bytes(self.encode({"boot_id": self.boot,
                                             "state_sha256": self.sha(self.assessment),
                                             "policy_sha256": self.sha(self.projection)}))
        self.policy.chmod(0o600)
        self.live = dict(self.before, MainPID="2345", InvocationID="b" * 32)
        self.assertEqual(self.proof("resume"), "guarded")

    def test_exact_live_and_restarted_actor_refusal(self):
        self.begin()
        self.assertEqual(self.proof("resume"), "live")
        self.live["MainPID"] = "9999"
        with self.assertRaises(AssertionError):
            self.proof("resume")

    def test_inactive_pid1_does_not_substitute_for_original_pid_death(self):
        self.begin()
        self.inactive()
        with self.assertRaises(AssertionError):
            self.proof("resume")
        self.tick = 1001
        self.assertEqual(self.proof("resume"), "stopped")

    def test_stopped_guardian_requires_other_passive_actors_alive(self):
        self.begin()
        self.inactive()
        self.tick = 1001
        self.missing_watchdog = True
        with self.assertRaises(AssertionError):
            self.proof("resume")
        self.assertFalse((self.control / "fresh-first-arm-stopped.json").exists())
        self.missing_watchdog = False
        self.assertEqual(self.proof("resume"), "stopped")

    def test_guarded_ready_requires_stop_link_and_exact_public_leaves(self):
        self.begin()
        self.guarded()
        self.dropin.write_bytes(b"foreign\n")
        with self.assertRaises(AssertionError):
            self.proof("resume")
        self.guarded_dropin_repair()
        self.receipt.write_bytes(self.encode(self.expected_receipt()))
        self.receipt.chmod(0o600)
        (self.control / "fresh-first-arm-stopped.json").unlink()
        with self.assertRaises((AssertionError, FileNotFoundError)):
            self.proof("resume")

    def test_ready_requires_fresh_guard_and_manager_pid1_state(self):
        self.begin()
        self.guarded()
        self.receipt.write_bytes(self.encode(self.expected_receipt()))
        self.receipt.chmod(0o600)
        self.assertEqual(self.proof("resume"), "ready")
        self.manager_service["ActiveState"] = "inactive"
        with self.assertRaises(AssertionError):
            self.proof("resume")

    def guarded_dropin_repair(self):
        self.dropin.write_bytes(("[Unit]\nRequires=aegis-device-egress-guard.service\n"
                                 "After=aegis-device-egress-guard.service\n[Service]\n"
                                 "Environment=AEGIS_DEVICE_GUARD_STATE=" + str(self.state) +
                                 "\nExecStartPre=+/usr/bin/nsenter --mount=/proc/1/ns/mnt "
                                 "--root=/proc/1/root -- /bin/bash " +
                                 str(self.helper) + " bind-manager\n"
                                 "ExecStartPost=+/usr/bin/nsenter --mount=/proc/1/ns/mnt "
                                 "--root=/proc/1/root -- /bin/bash " +
                                 str(self.helper) + " manager-ready\n"
                                 "TimeoutStartSec=90\n").encode())

    def expected_receipt(self):
        return {"schema": "aegis_auto_guard_first_arm_v1", "boot_id": self.boot,
                "candidate_sha256": self.sha(self.candidate.read_bytes()),
                "source_config_sha256": self.sha(self.config.read_bytes()),
                "relay_servers": self.facts["relay_servers"],
                "assessment_sha256": self.sha(self.assessment),
                "guard_unit_sha256": self.sha(self.unit_bytes),
                "manager": "systemd-networkd.service",
                "manager_dropin_sha256": self.sha(self.dropin.read_bytes()),
                "guardian_install_sha256": self.sha(self.install.read_bytes()),
                "policy_sha256": self.sha(self.projection),
                "installer_source_sha256": self.sha(self.installer.read_bytes())}

    def stop_script(self):
        code = isolated_code("PY_AUTO_FIRST_ARM_STOP", {
            "/var/lib/aegis-install/client/": str(self.guard) + "/"},
            ("show", "start"))
        calls = []

        class Poll:
            def register(self, fd, event):
                pass

            def poll(self, timeout):
                return [(0, 1)] if calls else []

        def shown(unit):
            if unit == "aegis-auto-guardian.service":
                return dict(self.live)
            return {"ActiveState": "active", "ControlPID": "0",
                    "NFileDescriptorStore": "0"}

        def stopped(*args, **kwargs):
            calls.append(args)
            self.inactive()
            return types.SimpleNamespace(returncode=0)

        env = {"_test_show": shown,
               "_test_start": lambda pid: self.tick,
               "_test_pidfd": lambda pid: os.open("/dev/null", os.O_RDONLY),
               "_test_poll": Poll,
               "_test_run": stopped}
        with mock.patch.object(sys, "argv", ["stop", str(self.control /
                                                   "fresh-first-arm-intent.json")]):
            exec(code, env)
        return len(calls)

    def test_stop_command_targets_only_intent_bound_actor(self):
        self.begin()
        self.live["InvocationID"] = "b" * 32
        with self.assertRaises(AssertionError):
            self.stop_script()
        self.assertEqual(self.live["ActiveState"], "active")
        self.live = dict(self.before)
        self.assertEqual(self.stop_script(), 1)
        self.assertEqual(self.live["ActiveState"], "inactive")


if __name__ == "__main__":
    unittest.main()
