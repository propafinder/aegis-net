"""Real temporary proc/config paths; inert manager command boundary."""
import ast
import json
import os
import pathlib
import signal
import subprocess
import sys
import tempfile
import types
import time
import unittest
from unittest import mock

SOURCE = pathlib.Path(__file__).with_name("validator.py")
UUID = "11111111-2222-3333-4444-555555555555"


class AssessmentDeadline(unittest.TestCase):
    def setUp(self):
        source = SOURCE.with_name("install.sh").read_text()
        body = source.split("device_assess_full_wide_host() {", 1)[1]
        body = body.split("python3 -c '\n", 1)[1].split("\n' \"$WIDE_INTERFACE\"", 1)[0]
        function = next(node for node in ast.parse(body).body if isinstance(node, ast.FunctionDef) and node.name == "run")
        module = ast.Module(body=[function], type_ignores=[])
        self.namespace = dict(subprocess=subprocess, os=os, signal=signal)
        exec(compile(module, "shipped-host-assessor-run", "exec"), self.namespace)

    def test_helper_budget_covers_owned_lock_and_plan(self):
        for arguments, expected in ((("bash", "/fixed/helper.sh", "assess-networkmanager", "eth0"), 40), (("ip", "-j", "route"), 15)):
            child = mock.Mock(returncode=0)
            child.communicate.return_value = (" result \n", None)
            with mock.patch.object(subprocess, "Popen", return_value=child) as spawn:
                self.assertEqual(self.namespace["run"](*arguments), "result")
            self.assertTrue(spawn.call_args.kwargs["start_new_session"])
            child.communicate.assert_called_once_with(timeout=expected)

    def test_timeout_kills_group_then_reaps(self):
        child = mock.Mock(pid=12345)
        child.communicate.side_effect = [subprocess.TimeoutExpired("fixture", 40), ("", None)]
        with mock.patch.object(subprocess, "Popen", return_value=child), mock.patch.object(os, "killpg") as kill:
            with self.assertRaises(subprocess.TimeoutExpired):
                self.namespace["run"]("bash", "/fixed/helper.sh", "assess-networkmanager", "eth0")
            kill.assert_called_once_with(12345, signal.SIGKILL)
            self.assertEqual(child.communicate.call_args_list, [mock.call(timeout=40), mock.call()])

    def test_real_timeout_stops_descendant_before_delayed_write(self):
        with tempfile.TemporaryDirectory(prefix="aegis-assessor-deadline-") as temporary:
            ready, delayed = (pathlib.Path(temporary) / name for name in ("ready", "late-write"))
            leaf = "import pathlib,time;pathlib.Path(" + repr(str(ready)) + ").write_text('ready');time.sleep(1);pathlib.Path(" + repr(str(delayed)) + ").write_text('escaped')"
            command = "import subprocess,sys,time;subprocess.Popen([sys.executable,'-c'," + repr(leaf) + "]);time.sleep(10)"
            actual_spawn = subprocess.Popen
            children = []
            def spawn(*args, **kwargs):
                child = actual_spawn(*args, **kwargs)
                children.append(child)
                communicate = child.communicate
                def bounded(*args, **kwargs):
                    if "timeout" in kwargs:
                        deadline = time.monotonic() + 3
                        while not ready.exists() and time.monotonic() < deadline:
                            time.sleep(0.01)
                        self.assertTrue(ready.exists(), "local descendant did not start")
                        kwargs["timeout"] = 0.05
                    return communicate(*args, **kwargs)
                child.communicate = bounded
                return child
            try:
                with mock.patch.object(subprocess, "Popen", side_effect=spawn):
                    with self.assertRaises(subprocess.TimeoutExpired):
                        self.namespace["run"](sys.executable, "-c", command)
                self.assertIsNotNone(children[0].poll())
                time.sleep(1.05)
                self.assertFalse(delayed.exists(), "descendant survived assessor timeout")
            finally:
                for child in children:
                    if child.poll() is None:
                        os.killpg(child.pid, signal.SIGKILL)
                        child.wait()


class Validation(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="aegis-nm-validator-")
        self.root = pathlib.Path(self.tmp.name).resolve()
        self.binary = self.root / "usr/sbin/NetworkManager"
        self.binary.parent.mkdir(parents=True)
        self.binary.write_text("inert executable fixture")
        self.binary.chmod(0o755)
        self.conf = self.root / "etc/NetworkManager/NetworkManager.conf"
        self.conf.parent.mkdir(parents=True)
        self.conf.write_text("[main]\n")
        proc = self.root / "proc/123"
        proc.mkdir(parents=True)
        (proc / "cmdline").write_bytes(str(self.binary).encode() + b"\0--no-daemon\0")
        (proc / "exe").symlink_to(self.binary)
        (proc / "stat").write_text("123 (NetworkManager) " + " ".join(["S"] + ["0"] * 18 + ["100"]))
        source = SOURCE.read_text()
        for prefix in ("/usr", "/etc", "/var/lib", "/run", "/proc"):
            source = source.replace('"' + prefix, '"' + str(self.root) + prefix)
        source = source.replace("os.geteuid() == 0", "os.geteuid() == " + str(os.geteuid()))
        source = source.replace("value.st_uid == 0", "value.st_uid == " + str(os.getuid()))
        source = source.replace("for ancestor in (path, *path.parents):", "for ancestor in (path, *[p for p in path.parents if p == FIXTURE_ROOT or FIXTURE_ROOT in p.parents]):")
        self.module = types.ModuleType("fixture_nm_validator")
        self.module.FIXTURE_ROOT = self.root
        exec(compile(source, str(SOURCE), "exec"), self.module.__dict__)
        self.calls = []
        self.printed = "[main]\ndhcp=internal\n"
        self.argv = str(self.binary) + " --no-daemon"
        self.kind = "802-3-ethernet"
        self.interface = "eth0"
        self.methods = ("auto", "auto")
        self.autoconnect = "yes"
        self.permissions = ""
        self.applied_methods = None
        self.applied_kind = None
        self.applied_interface = None
        self.applied_uuid = UUID
        self.applied_version = 1
        self.on_bus = lambda: None
        self.bus_override = None
        self.on_print = lambda: None
        self.on_connection = lambda: None
        self.module.run = self.run_command

    def tearDown(self):
        self.tmp.cleanup()

    def run_command(self, *args):
        self.calls.append(args)
        if args[0] == str(self.binary):
            self.on_print()
            return self.printed
        if args[:4] == ("systemctl", "show", "NetworkManager.service", "-p"):
            if args[4] == "ExecStart":
                return "{ path=" + str(self.binary) + " ; argv[]=" + self.argv + " ; ignore_errors=no ; pid=123 ; }"
            if args[4] == "MainPID":
                return "123"
        if args[0] == "busctl":
            self.on_bus()
            if self.bus_override is not None:
                return self.bus_override
            v4, v6 = self.applied_methods or self.methods
            variant = lambda value: {"type": "s", "data": value}
            return json.dumps({"type": "a{sa{sv}}t", "data": [
                {"connection": {"uuid": variant(self.applied_uuid), "type": variant(self.applied_kind if self.applied_kind is not None else self.kind), "interface-name": variant(self.applied_interface if self.applied_interface is not None else self.interface)},
                 "ipv4": {"method": variant(v4)}, "ipv6": {"method": variant(v6)},
                 "802-11-wireless-security": {"psk": variant("PRIVATE SYNTHETIC APPLIED VALUE MUST NOT ESCAPE")}}, self.applied_version]})
        if args[0] == "nmcli":
            self.on_connection()
            name = args[args.index("--get-values") + 1]
            return {"GENERAL.CON-UUID": UUID, "GENERAL.DBUS-PATH": "/org/freedesktop/NetworkManager/Devices/2", "connection.type": self.kind,
                    "connection.interface-name": self.interface, "connection.autoconnect": self.autoconnect,
                    "connection.permissions": self.permissions, "ipv4.method": self.methods[0], "ipv6.method": self.methods[1]}[name]
        raise AssertionError(args)

    def valid(self, mode="plan", expected=None):
        return self.module.validate(mode, "eth0", expected)

    def refused(self, mode="plan", expected=None):
        with self.assertRaises((ValueError, OSError)):
            self.valid(mode, expected)

    def test_explicit_internal_live_exact_connection(self):
        expected = {"manager_connection_uuid": UUID, "manager_ipv4_method": "auto", "manager_ipv6_method": "auto"}
        result = self.valid("live", expected)
        self.assertTrue(result["dhcp4"] and result["dhcp6"] and result["explicit_internal"])

    def test_implicit_default_is_only_a_plan(self):
        self.printed = "[main]\n# dhcp=internal\n"
        self.assertFalse(self.valid()["explicit_internal"])
        self.refused("disk")
        self.refused("live", {})

    def test_explicit_external_or_unknown_refused(self):
        for value in ("dhclient", "dhcpcd", "external", "", "internal,dhclient"):
            with self.subTest(value=value):
                self.printed = "[main]\ndhcp=" + value + "\n"
                self.refused()

    def test_effective_override_wins_over_source_file(self):
        self.conf.write_text("[main]\ndhcp=internal\n")
        self.printed = "[main]\ndhcp=dhclient\n"
        self.refused()

    def test_ambiguous_default_section_refused(self):
        self.printed = "[DEFAULT]\ndhcp=internal\n[main]\n"
        self.refused("disk")

    def test_custom_manager_config_argv_refused(self):
        self.argv += " --config /etc/unreviewed.conf"
        self.refused()

    def test_running_argv_differs_from_loaded_unit(self):
        (self.root / "proc/123/cmdline").write_bytes(str(self.binary).encode() + b"\0--no-daemon\0--config\0other\0")
        self.refused()

    def test_service_executable_replaced(self):
        other = self.root / "other-executable"
        other.write_text("foreign")
        exe = self.root / "proc/123/exe"
        exe.unlink()
        exe.symlink_to(other)
        self.refused()

    def test_config_mutation_during_print_refused(self):
        self.on_print = lambda: self.conf.write_text("[main]\ndhcp=dhclient\n")
        self.refused()

    def test_process_restart_during_connection_read_refused(self):
        self.on_connection = lambda: (self.root / "proc/123/stat").write_text("123 (NetworkManager) " + " ".join(["S"] + ["0"] * 18 + ["200"]))
        self.refused()

    def test_writable_or_linked_config_refused(self):
        self.conf.chmod(0o666)
        self.refused()
        self.conf.chmod(0o644)
        os.link(self.conf, self.root / "linked-config")
        self.refused()

    def test_symlinked_configuration_refused(self):
        original = self.root / "original-conf"
        self.conf.rename(original)
        self.conf.symlink_to(original)
        self.refused()

    def test_oversized_config_refused(self):
        self.conf.write_bytes(b"x" * 65537)
        self.refused()

    def test_shared_or_unknown_method_refused(self):
        for methods in (("shared", "auto"), ("manual", "shared"), ("auto", "future")):
            with self.subTest(methods=methods):
                self.methods = methods
                self.refused()

    def test_pinned_connection_or_policy_change_refused(self):
        for expected in ({"manager_connection_uuid": "aaaaaaaa-2222-3333-4444-555555555555"}, {"manager_ipv4_method": "manual"}):
            with self.subTest(expected=expected):
                self.refused("live", expected)

    def test_user_session_and_disabled_autoconnect_refused(self):
        self.permissions = "user:alice:"
        self.refused()
        self.permissions = ""
        self.autoconnect = "no"
        self.refused()

    def test_unknown_connection_interface_or_type_refused(self):
        self.interface = "eth1"
        self.refused()
        self.interface = "eth0"
        self.kind = "bridge"
        self.refused()

    def test_manual_dhcp_families_and_wifi(self):
        self.methods = ("manual", "disabled")
        self.kind = "802-11-wireless"
        result = self.valid()
        self.assertFalse(result["dhcp4"] or result["dhcp6"])

    def test_stored_profile_is_not_applied_policy(self):
        self.applied_methods = ("manual", "disabled")
        expected = {"manager_connection_uuid": UUID, "manager_ipv4_method": "auto", "manager_ipv6_method": "auto"}
        self.assertEqual(self.valid()["manager_ipv4_method"], "auto")
        self.refused("live", expected)

    def test_applied_uuid_differs(self):
        self.applied_uuid = "aaaaaaaa-2222-3333-4444-555555555555"
        self.refused("live", {"manager_connection_uuid": UUID})

    def test_applied_type_differs_with_same_uuid_and_methods(self):
        self.applied_kind = "802-11-wireless"
        self.refused("live", {"manager_connection_uuid": UUID})

    def test_applied_interface_binding_differs_with_same_uuid(self):
        for stored, applied in (("eth0", ""), ("", "eth0")):
            with self.subTest(stored=stored, applied=applied):
                self.interface, self.applied_interface = stored, applied
                self.refused("live", {"manager_connection_uuid": UUID})

    def test_exact_type_and_interface_projection_preserves_public_schema(self):
        for kind in ("802-3-ethernet", "802-11-wireless"):
            for interface in ("eth0", ""):
                self.kind, self.interface = kind, interface
                result = self.valid("live", {"manager_connection_uuid": UUID})
                self.assertNotIn("connection_type", result)
                self.assertNotIn("connection_interface", result)

    def test_applied_version_changes_between_reads(self):
        def changed():
            self.applied_version += 1
        self.on_bus = changed
        self.refused("live", {"manager_connection_uuid": UUID})

    def test_malformed_or_duplicate_applied_reply_refused(self):
        for raw in ('{"type":"a{sa{sv}}t","data":[]}', '{"type":"a{sa{sv}}t","type":"a{sa{sv}}t","data":[]}', '{"type":"wrong","data":[{},1]}'):
            with self.subTest(raw=raw):
                self.bus_override = raw
                self.refused("live", {"manager_connection_uuid": UUID})

    def test_applied_projection_omits_unrequested_private_values(self):
        result = self.valid("live", {"manager_connection_uuid": UUID})
        self.assertNotIn("PRIVATE", json.dumps(result))
        self.assertNotIn("PRIVATE", repr(self.calls))
        bus_calls = [args for args in self.calls if args[0] == "busctl"]
        self.assertEqual(len(bus_calls), 2)
        self.assertTrue(all("--auto-start=no" in args and "--allow-interactive-authorization=no" in args and "GetAppliedConnection" in args for args in bus_calls))

    def test_disk_check_does_not_depend_on_not_started_daemon(self):
        (self.root / "proc/123/cmdline").unlink()
        result = self.valid("disk")
        self.assertTrue(result["explicit_internal"])
        self.assertFalse(any(args[0] == "nmcli" for args in self.calls))


if __name__ == "__main__":
    unittest.main()
