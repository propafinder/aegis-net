"""B-06 S16c: harness/installed-run.sh against fake system commands.

Every system command the harness may run (scutil, systemextensionsctl,
route, ifconfig, nc, dig, lsof, pgrep, the aegis-ne-host shim, and a sudo
trap) is a fake on PATH backed by one scenario file; nothing here touches a
real network service, VPN configuration or the installed app. HOME and the
artifacts directory are temporary, so the coordination locks are fakes too.
"""
import json
import os
import pathlib
import re
import signal
import subprocess
import sys
import tempfile
import time
import unittest


PACKAGE = pathlib.Path(__file__).resolve().parents[1]
HARNESS = PACKAGE / "harness" / "installed-run.sh"
SID = "0F5C4B6E-2D2A-4C1E-9B59-3A8E1D2C4B7F"
GEN = "6B29FC40-CA47-1067-B31D-00DD010662DA"
RELAY = "192.168.1.107:443"
TOOLS = ["scutil", "systemextensionsctl", "route", "ifconfig", "nc", "dig",
         "lsof", "pgrep", "sudo"]
CHECKS = ["utun_interface", "default_route_tunnel", "tcp4_echo", "tcp6_echo",
          "udp4_echo", "dns_a_fake_ip", "fake_ip_tcp_echo", "dns_txt",
          "dns_aaaa_v6", "dns_tcp", "dns_resolver", "relay_socket"]

FAKE = r'''
import fcntl, glob, json, os, sys, time
root = os.environ["FAKE_ROOT"]
tool, args = sys.argv[1], sys.argv[2:]
scen = json.load(open(os.path.join(root, "scenario.json")))
lock = open(os.path.join(root, "state.lock"), "a")
fcntl.flock(lock, fcntl.LOCK_EX)
with open(os.path.join(root, "calls.log"), "a") as log:
    log.write(json.dumps({"tool": tool, "args": args, "t": time.time()}) + "\n")
state_path = os.path.join(root, "state.json")
try:
    state = json.load(open(state_path))
except FileNotFoundError:
    state = {"status": "Connected" if scen.get("initially_connected") else "Disconnected",
             "ever_connected": bool(scen.get("initially_connected"))}
def save():
    with open(state_path + ".tmp", "w") as handle:
        json.dump(state, handle)
    os.replace(state_path + ".tmp", state_path)
def tunnel_up():
    return state["status"] == "Connected" or (scen.get("stuck") and state["ever_connected"]) \
        or (scen.get("lingering_address") and state["ever_connected"]) \
        or scen.get("preexisting_tunnel_address", False)
def route_up():
    return state["status"] == "Connected" or (scen.get("stuck") and state["ever_connected"])
def out(text):
    sys.stdout.write(text)
if tool in scen.get("hang", []):
    fcntl.flock(lock, fcntl.LOCK_UN)
    time.sleep(1000)
code = 0
if tool == "sudo":
    code = 1
elif tool == "systemextensionsctl":
    out("1 extension(s)\n--- com.apple.system_extension.network_extension\n"
        "enabled\tactive\tteamID\tbundleID (version)\tname\t[state]\n")
    for value in scen.get("sysext", ["activated enabled"]):
        out("*\t*\tTEAMID0000\tdev.aegis.macos.PacketTunnel (8/8)\tAEGIS\t[%s]\n" % value)
elif tool == "aegis-ne-host":
    verb = args[0] if args else ""
    if verb in scen.get("hang_verbs", []):
        fcntl.flock(lock, fcntl.LOCK_UN)
        time.sleep(1000)
    if verb == "--ping":
        if scen.get("ping_exit", 0):
            sys.stderr.write("xpc_service_unavailable\n")
            code = scen["ping_exit"]
        else:
            out(json.dumps({"schema": "aegis-b06-provider-xpc-v1", "verb": "ping", "report": {
                "identity_present": scen.get("identity_present", True),
                "container_open": {"errno": 0, "getpath_errno": 0, "path_matched": True,
                                   "admitted": scen.get("admitted", True)},
                "session_phase": "none"}}) + "\n")
    elif verb == "--list":
        profiles = scen.get("profiles", [{}])
        for index, profile in enumerate(profiles):
            out("profile index=%d owner_generation=%s scutil_service_id=%s intent_valid=%s "
                "enabled=true on_demand_enabled=%s native_vpn_status=1\n" % (
                    index, profile.get("gen", "%s" % GEN), profile.get("sid", "%s" % SID),
                    profile.get("intent_valid", "true"), profile.get("on_demand", "false")))
        out("profiles=%d native_acceptance=false\n" % len(profiles))
        if scen.get("codex_lock_on_list"):
            locks = os.path.join(os.environ["HOME"], ".aegis-local", "locks")
            os.makedirs(locks, exist_ok=True)
            open(os.path.join(locks, "timing-peer"), "w").write("codex\n")
    elif verb == "--connect":
        armed = False
        for path in glob.glob(os.path.join(os.environ["FAKE_ARTIFACTS"], "*", "rollback.log")):
            for line in open(path):
                if line.startswith("rollback_armed pid="):
                    pid = int(line.split()[1].split("=")[1])
                    try:
                        os.kill(pid, 0)
                        armed = True
                    except OSError:
                        pass
        state["rollback_armed_at_connect"] = armed
        state["connect_args"] = args
        # A stuck route models a half-applied tunnel, even after a failed start.
        state["ever_connected"] = state["ever_connected"] or bool(scen.get("stuck"))
        if scen.get("connect_exit", 0):
            sys.stderr.write("owner_generation=%s start_failed\n" % args[2])
            code = scen["connect_exit"]
        else:
            result = scen.get("connect_result", "Connected")
            state["status"] = result
            state["ever_connected"] = state["ever_connected"] or result == "Connected"
            out("owner_generation=%s profile_sha256=%s native_vpn_status=2 native_acceptance=false\n"
                % (args[2], "a" * 64))
    elif verb == "--disconnect":
        if scen.get("replace_own_lock"):
            path = os.path.join(os.environ["HOME"], ".aegis-local", "locks", "timing-self")
            os.unlink(path)
            open(path, "w").write("someone else\n")
        if scen.get("disconnect_works", True):
            state["status"] = "Disconnected"
        # Successive `scutil --nc status` answers right after the disconnect.
        state["status_queue"] = list(scen.get("status_after_disconnect", []))
        if scen.get("disconnect_exit", 0):
            sys.stderr.write("exact_owned_profile_required\n")
            code = scen["disconnect_exit"]
        else:
            out("owner_generation=%s native_vpn_status=1 native_acceptance=false\n" % args[2])
    elif verb == "--emergency-stop":
        if scen.get("emergency_works", True):
            state["status"] = "Disconnected"
        out("stopped=1\n")
    else:
        code = 2
elif tool == "scutil":
    if args[:2] == ["--nc", "list"]:
        out("Available network connection services in the current set (*=enabled):\n")
        if scen.get("sid_listed", True):
            out('* (%s)   %s VPN (dev.aegis.macos) "AEGIS" [VPN:dev.aegis.macos]\n'
                % (state["status"], SID))
    elif args[:2] == ["--nc", "status"]:
        queue = state.get("status_queue") or []
        shown = queue.pop(0) if queue else state["status"]
        state["status_queue"] = queue
        out("%s\nExtended Status <dictionary> {\n}\n" % shown)
    elif args[:2] == ["--nc", "stop"]:
        if scen.get("scutil_stop_works", True):
            state["status"] = "Disconnected"
    elif args == ["--dns"]:
        server = "198.19.255.2" if state["status"] == "Connected" else "192.168.1.1"
        out("DNS configuration\n\nresolver #1\n  nameserver[0] : %s\n  flags    : Request A records\n" % server)
    else:
        code = 64
elif tool == "route":
    iface = "utun7" if route_up() else scen.get("physical", "en0")
    out("   route to: default\ndestination: default\n       mask: default\n    gateway: 192.168.1.1\n"
        "  interface: %s\n      flags: <UP,GATEWAY,DONE,STATIC,PRCLONING,GLOBAL>\n" % iface)
elif tool == "ifconfig":
    out("lo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST> mtu 16384\n\tinet 127.0.0.1 netmask 0xff000000\n"
        "en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500\n"
        "\tinet 192.168.1.50 netmask 0xffffff00 broadcast 192.168.1.255\n"
        "utun0: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1380\n\tinet6 fe80::1%utun0 prefixlen 64\n")
    if tunnel_up():
        out("utun7: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1280\n"
            "\tinet 198.19.255.1 --> 198.19.255.1 netmask 0xffffffff\n")
elif tool == "nc":
    flags = [a for a in args if a.startswith("-")]
    host, port = [a for a in args if not a.startswith("-")][-2:]
    if "-z" in flags:
        code = 0 if scen.get("relay_listening", True) and "%s:%s" % (host, port) == "192.168.1.107:443" else 1
    else:
        data = sys.stdin.read()
        echo = {"192.0.2.10", "2001:db8::10", scen.get("dns_a", "198.18.0.7")}
        if tunnel_up() and port == "7" and host in echo and host not in scen.get("broken_echo", []):
            out(data)
elif tool == "dig":
    server = [a[1:] for a in args if a.startswith("@")][0]
    qtype = args[-1]
    if not tunnel_up():
        out(";; connection timed out; no servers could be reached\n")
        code = 9
    elif qtype == "A" and server == "198.19.255.2":
        out(scen.get("dns_a", "198.18.0.7") + "\n")
    elif qtype == "TXT" and server == "198.19.255.2":
        out('"aegis-b06-probe"\n')
    elif qtype == "AAAA" and server == "fd00:ae61::2" and "-6" in args:
        out("2001:db8::10\n")
elif tool == "pgrep":
    pids = scen.get("provider_pids", ["4242"])
    out("".join(p + "\n" for p in pids))
    code = 0 if pids else 1
elif tool == "lsof":
    mode = scen.get("lsof", "ok")
    if mode == "denied":
        code = 1
    else:
        out("COMMAND    PID USER   FD   TYPE DEVICE SIZE/OFF NODE NAME\n")
        target = "192.168.1.107:443" if mode == "ok" else "192.168.1.9:443"
        out("aegis-ne- 4242 root    9u  IPv4 0x1      0t0  TCP 192.168.1.50:50000->%s (ESTABLISHED)\n" % target)
save()
sys.exit(code)
'''


class HarnessFixture(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="aegis-s16c-")
        self.addCleanup(self.temp.cleanup)
        self.root = pathlib.Path(self.temp.name)
        self.home = self.root / "home"
        self.home.mkdir()
        self.artifacts = self.root / "artifacts"
        self.bin = self.root / "bin"
        self.bin.mkdir()
        (self.root / "fake.py").write_text("SID = %r\nGEN = %r\n%s" % (SID, GEN, FAKE))
        self.app = self.root / "AEGIS.app"
        (self.app / "Contents" / "MacOS").mkdir(parents=True)
        for path, tool in [(self.bin / t, t) for t in TOOLS] + [
                (self.app / "Contents" / "MacOS" / "aegis-ne-host", "aegis-ne-host")]:
            path.write_text('#!/bin/bash\nexec %s -I -B %s %s "$@"\n'
                            % (sys.executable, self.root / "fake.py", tool))
            path.chmod(0o755)
        self.addCleanup(self.kill_rollbacks)

    @property
    def locks(self):
        return self.home / ".aegis-local" / "locks"

    def kill_rollbacks(self):
        for pid_file in self.artifacts.glob("*/watchdog.pid"):
            try:
                os.kill(int(pid_file.read_text()), signal.SIGKILL)
            except (OSError, ValueError):
                pass
        for log in self.artifacts.glob("*/rollback.log"):
            for match in re.finditer(r"^rollback_armed pid=(\d+)", log.read_text(), re.M):
                try:
                    os.kill(int(match.group(1)), signal.SIGKILL)
                except OSError:
                    pass

    def env(self):
        return {"PATH": "%s:/usr/bin:/bin:/usr/sbin:/sbin" % self.bin, "HOME": str(self.home),
                "FAKE_ROOT": str(self.root), "FAKE_ARTIFACTS": str(self.artifacts),
                "LC_ALL": "C"}

    def command(self, *extra, app=None):
        return ["/bin/bash", str(HARNESS), "--app", str(app or self.app),
                "--artifacts-dir", str(self.artifacts), *extra]

    def run_harness(self, scenario=None, *extra, app=None, timeout=60):
        (self.root / "scenario.json").write_text(json.dumps(scenario or {}))
        result = subprocess.run(self.command(*extra, app=app), env=self.env(), capture_output=True,
                                text=True, timeout=timeout, check=False)
        self.assertNotIn("sudo", [c["tool"] for c in self.calls()], "sudo must never run")
        return result, self.receipt(result.stdout)

    def start_harness(self, scenario, *extra, session=False):
        (self.root / "scenario.json").write_text(json.dumps(scenario))
        return subprocess.Popen(self.command(*extra), env=self.env(), stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, text=True, start_new_session=session)

    def receipt(self, stdout):
        match = re.search(r"^receipt=(.+)$", stdout, re.M)
        return json.loads(pathlib.Path(match.group(1)).read_text()) if match else None

    def calls(self):
        path = self.root / "calls.log"
        return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []

    def host_verbs(self):
        return [c["args"][0] for c in self.calls() if c["tool"] == "aegis-ne-host"]

    def state(self):
        return json.loads((self.root / "state.json").read_text())

    def by_name(self, receipt, kind):
        return {entry["name"]: entry for entry in receipt[kind]}

    @staticmethod
    def alive(pid):
        try:
            os.kill(pid, 0)
        except OSError:
            return False
        return True

    def assert_released(self, receipt):
        self.assertFalse((self.locks / "timing-self").exists())
        if "lock_path" in receipt:
            self.assertIs(receipt["lock_removed"], True)

    def assert_rollback_exits(self, receipt):
        """A cancelled rollback exits once the harness has, leaving the lock to it."""
        self.wait_for(lambda: not self.alive(receipt["rollback_pid"]), seconds=5)
        log = (pathlib.Path(receipt["run_dir"]) / "rollback.log").read_text()
        self.assertTrue(log.endswith("rollback_cancelled\nrollback_lock_absent\n"), log)

    def assert_lock_kept(self, receipt, reason):
        """The lock stays, still this run's, annotated for whoever releases it."""
        text = (self.locks / "timing-self").read_text()
        token = "owner=claude pid=%s run=%s" % (
            re.search(r"pid=(\d+) ", text).group(1), pathlib.Path(receipt["run_dir"]).name)
        self.assertIn(token + "\n", text)
        self.assertIn("kept=%s rollback_pid=" % reason, text)
        self.assertIs(receipt["lock_removed"], False)
        self.assertEqual(receipt["lock_kept_reason"], reason)

    @staticmethod
    def ps(pid, column):
        result = subprocess.run(["ps", "-o", column + "=", "-p", str(pid)], capture_output=True,
                                text=True, check=False)
        return result.stdout.strip()

    @staticmethod
    def descendants(root):
        table = subprocess.run(["ps", "-A", "-o", "pid=,ppid="], capture_output=True, text=True,
                               check=True).stdout.split()
        children = {}
        for pid, ppid in zip(table[0::2], table[1::2]):
            children.setdefault(int(ppid), []).append(int(pid))
        found, todo = [], [root]
        while todo:
            for child in children.get(todo.pop(), []):
                found.append(child)
                todo.append(child)
        return found

    def rollback_log(self):
        return next(self.artifacts.glob("*/rollback.log"))

    def rollback_pid(self):
        self.wait_for(lambda: re.search(r"^rollback_armed pid=\d+", self.rollback_log().read_text(), re.M))
        return int(re.search(r"^rollback_armed pid=(\d+)", self.rollback_log().read_text(), re.M).group(1))

    def status_calls_after_disconnect(self):
        calls = self.calls()
        at = max(i for i, c in enumerate(calls) if c["args"][:1] == ["--disconnect"])
        return [c for c in calls[at:] if c["tool"] == "scutil" and c["args"][:2] == ["--nc", "status"]]

    def interrupt_after_connect(self, scenario, *extra, sig=signal.SIGINT):
        proc = self.start_harness(scenario, *extra)
        try:
            self.wait_for(lambda: "--connect" in self.host_verbs())
            proc.send_signal(sig)
            stdout, _ = proc.communicate(timeout=60)
        finally:
            if proc.poll() is None:
                proc.kill()
        return proc.returncode, self.receipt(stdout)

    def wait_for(self, predicate, seconds=15):
        deadline = time.time() + seconds
        while time.time() < deadline:
            if predicate():
                return
            time.sleep(0.1)
        self.fail("condition not reached")


class StaticTests(unittest.TestCase):
    def test_bash_syntax(self):
        subprocess.run(["/bin/bash", "-n", str(HARNESS)], check=True)

    def test_no_privilege_escalation_or_absolute_system_tools(self):
        text = HARNESS.read_text()
        self.assertIsNone(re.search(r"\bsudo\b|\bdoas\b|osascript|with administrator", text))
        # Every system tool comes from PATH, so no absolute path bypasses review.
        self.assertIsNone(re.search(r"/usr/sbin/|(?<![\w/])/sbin/", text))
        for forbidden in ("--save-profile", "--remove-profile", "--import", "--forget-identity",
                          "--request-activation", "notarytool"):
            self.assertNotIn(forbidden, text)


class DryRunTests(HarnessFixture):
    def test_dry_run_prints_every_command_and_runs_nothing(self):
        result, receipt = self.run_harness({}, "--dry-run")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIsNone(receipt)
        host = str(self.app / "Contents/MacOS/aegis-ne-host")
        for expected in ["systemextensionsctl list", host + " --ping", host + " --list",
                         "scutil --nc list", "nc -z -w2 192.168.1.107 443", "nohup perl",
                         host + " --connect dev.aegis.macos.PacketTunnel",
                         "scutil --nc status", "ifconfig", "route -n get default",
                         "nc -w2 192.0.2.10 7", "nc -6 -w2 2001:db8::10 7", "nc -u -w2 192.0.2.10 7",
                         "dig +short +time=2 +tries=1 @198.19.255.2 probe.test A",
                         "dig +short +time=2 +tries=1 @198.19.255.2 probe.test TXT",
                         "dig -6 +short +time=2 +tries=1 @fd00:ae61::2 probe.test AAAA",
                         "dig +tcp +short +time=2 +tries=1 @198.19.255.2 probe.test TXT",
                         "scutil --dns", "pgrep -x aegis-ne-provider", "lsof -nP -a -p",
                         host + " --disconnect dev.aegis.macos.PacketTunnel",
                         "scutil --nc stop", host + " --emergency-stop"]:
            self.assertIn(expected, result.stdout)
        self.assertEqual(self.calls(), [])
        self.assertFalse(self.artifacts.exists())
        self.assertFalse(self.locks.exists())

    def test_checks_only_dry_run_has_no_connect_or_rollback(self):
        result, _ = self.run_harness({}, "--dry-run", "--checks-only")
        self.assertEqual(result.returncode, 0, result.stderr)
        for absent in ("--connect", "--disconnect", "nohup", "--emergency-stop"):
            self.assertNotIn(absent, result.stdout)
        self.assertEqual(self.calls(), [])


class UsageTests(HarnessFixture):
    def test_usage_errors_run_nothing(self):
        for extra in (["--rollback-seconds", "0"], ["--rollback-seconds", "301"],
                      ["--rollback-seconds", "09"], ["--hard-timeout", "19"],
                      ["--hard-timeout", "121"], ["--relay", "192.168.1.107"],
                      ["--relay", "198.19.255.1:443"], ["--relay", "127.0.0.1:443"],
                      ["--relay", "192.168.01.207:443"], ["--relay", "192.168.1.107:0"],
                      ["--relay", "192.168.1.107:65536"], ["--relay", "192.168.1.107:99999"],
                      ["--relay", "192.168.1.107:100000"], ["--relay", "192.168.1.107:04430"],
                      ["--rollback-seconds", "91"], ["--hard-timeout", "0120"],
                      ["--artifacts-dir", "relative"], ["--bogus"], ["--relay"]):
            with self.subTest(extra=extra):
                result, receipt = self.run_harness({}, *extra)
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertIsNone(receipt)
        self.assertEqual(self.calls(), [])
        self.assertFalse(self.artifacts.exists())

    def test_five_digit_relay_ports_are_accepted(self):
        for port in ("10000", "50443", "65535"):
            with self.subTest(port=port):
                result, _ = self.run_harness({}, "--dry-run", "--relay", "192.168.1.107:" + port)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("nc -z -w2 192.168.1.107 %s" % port, result.stdout)
        self.assertEqual(self.calls(), [])


class WindowTests(HarnessFixture):
    def test_window_pass_records_receipt_and_releases_everything(self):
        result, receipt = self.run_harness({})
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(receipt["outcome"], "pass")
        self.assertEqual(receipt["exit_code"], 0)
        self.assertEqual(receipt["mode"], "window")
        self.assertEqual(receipt["schema"], "aegis-b06-installed-window-receipt-v1")
        self.assertEqual(receipt["service_id"], SID)
        self.assertEqual(receipt["owner_generation"], GEN)
        self.assertEqual(receipt["relay"], RELAY)
        self.assertEqual(receipt["physical_interface"], "en0")
        self.assertEqual(receipt["tunnel_interface"], "utun7")
        self.assertEqual(receipt["rollback_seconds"], 90)
        self.assertEqual(receipt["hard_timeout_seconds"], 120)
        self.assertRegex(receipt["harness_sha256"], r"^[0-9a-f]{64}$")
        self.assertRegex(receipt["host_sha256"], r"^[0-9a-f]{64}$")
        self.assertIs(receipt["disconnect_verified"], True)
        self.assertIs(receipt["rollback_cancelled"], True)
        self.assert_released(receipt)
        self.assertEqual(receipt["lock_released_by"], "harness")
        self.assertTrue(all(p["status"] == "pass" for p in receipt["preconditions"]))
        self.assertIn("ppid=1 pgid=%d " % receipt["rollback_pid"],
                      self.by_name(receipt, "rollback")["armed"]["detail"])
        self.assertEqual([c["name"] for c in receipt["checks"]], CHECKS)
        self.assertTrue(all(c["status"] == "pass" for c in receipt["checks"]), receipt["checks"])
        self.assertEqual(receipt["checks_passed"], len(CHECKS))
        self.assertEqual(self.by_name(receipt, "checks")["dns_a_fake_ip"]["detail"], "answer=198.18.0.7")
        # The rollback was alive when --connect ran, and is gone afterwards.
        self.assertIs(self.state()["rollback_armed_at_connect"], True)
        self.assertEqual(self.state()["connect_args"],
                         ["--connect", "dev.aegis.macos.PacketTunnel", GEN, "192.168.1.107"])
        rollback = self.by_name(receipt, "rollback")
        connect = self.by_name(receipt, "connect")
        self.assertLess(rollback["armed"]["seq"], connect["host_connect"]["seq"])
        self.assert_rollback_exits(receipt)
        log = (pathlib.Path(receipt["run_dir"]) / "rollback.log").read_text()
        self.assertIn("rollback_armed", log)
        self.assertIn("rollback_cancelled", log)
        self.assertNotIn("rollback_fired", log)
        self.assertEqual(self.host_verbs(), ["--ping", "--list", "--connect", "--disconnect"])
        verified = self.by_name(receipt, "disconnect")["verified_after_host_disconnect"]
        self.assertEqual(verified["status"], "pass")
        self.assertIn("status=Disconnected polls=2", verified["detail"])
        self.assertEqual(oct(pathlib.Path(receipt["run_dir"], "receipt.json").stat().st_mode & 0o777), "0o600")

    def test_each_precondition_refuses_before_rollback_or_connect(self):
        cases = [
            ({"sysext": ["activated waiting for user"]}, "system_extension_activated"),
            ({"sysext": []}, "system_extension_activated"),
            ({"sysext": ["activated enabled", "activated enabled"]}, "system_extension_activated"),
            ({"ping_exit": 69}, "provider_ping"),
            ({"identity_present": False}, "provider_ping"),
            ({"admitted": False}, "provider_ping"),
            ({"profiles": []}, "single_profile"),
            ({"profiles": [{}, {}]}, "single_profile"),
            ({"profiles": [{"on_demand": "true"}]}, "single_profile"),
            ({"profiles": [{"intent_valid": "false"}]}, "single_profile"),
            ({"profiles": [{"sid": "unavailable"}]}, "single_profile"),
            ({"profiles": [{"gen": "unavailable"}]}, "single_profile"),
            ({"sid_listed": False}, "scutil_service_listed"),
            ({"relay_listening": False}, "relay_listening"),
            ({"initially_connected": True}, "tunnel_disconnected"),
            ({"physical": "utun3"}, "physical_default_route"),
            ({"preexisting_tunnel_address": True}, "physical_default_route"),
        ]
        for scenario, name in cases:
            with self.subTest(scenario=scenario):
                for path in ("calls.log", "state.json"):
                    (self.root / path).unlink(missing_ok=True)
                result, receipt = self.run_harness(scenario)
                self.assertEqual(result.returncode, 3, result.stderr)
                self.assertEqual(receipt["outcome"], "refused")
                failed = [p for p in receipt["preconditions"] if p["status"] != "pass"]
                self.assertEqual([p["name"] for p in failed], [name])
                self.assertNotIn("--connect", self.host_verbs())
                self.assertNotIn("rollback_pid", receipt)
                self.assertNotIn("lock_path", receipt)
                self.assertFalse((self.locks / "timing-self").exists())

    def test_missing_app_refuses(self):
        result, receipt = self.run_harness({}, app=self.root / "Missing.app")
        self.assertEqual(result.returncode, 3)
        self.assertEqual(receipt["preconditions"][-1]["name"], "app_installed")
        self.assertEqual(self.calls(), [])

    def test_timing_codex_lock_refuses_before_any_command(self):
        self.locks.mkdir(parents=True)
        (self.locks / "timing-peer").write_text("start=now purpose=native39\n")
        result, receipt = self.run_harness({})
        self.assertEqual(result.returncode, 4)
        self.assertEqual(receipt["outcome"], "refused_timing_codex")
        self.assertEqual(self.calls(), [])
        self.assertFalse((self.locks / "timing-self").exists())
        # A dangling symlink is a lock too.
        (self.locks / "timing-peer").unlink()
        (self.locks / "timing-peer").symlink_to(self.root / "absent")
        result, _ = self.run_harness({})
        self.assertEqual(result.returncode, 4)

    def test_codex_lock_taken_during_preconditions_refuses_before_connect(self):
        result, receipt = self.run_harness({"codex_lock_on_list": True})
        self.assertEqual(result.returncode, 4, result.stderr)
        self.assertEqual(receipt["outcome"], "refused_timing_codex")
        self.assertEqual(receipt["preconditions"][-1]["name"], "timing_codex_lock_absent_after_lock")
        self.assertNotIn("--connect", self.host_verbs())
        self.assertNotIn("rollback_pid", receipt)
        self.assert_released(receipt)

    def test_existing_own_lock_refuses_and_is_left_alone(self):
        self.locks.mkdir(parents=True)
        (self.locks / "timing-self").write_text("another window\n")
        result, receipt = self.run_harness({})
        self.assertEqual(result.returncode, 3)
        self.assertEqual(receipt["preconditions"][-1]["name"], "timing_lock_created")
        self.assertEqual((self.locks / "timing-self").read_text(), "another window\n")
        self.assertNotIn("--connect", self.host_verbs())

    def test_check_failure_stops_tunnel_and_cancels_rollback(self):
        result, receipt = self.run_harness({"dns_a": "8.8.8.8"})
        self.assertEqual(result.returncode, 1)
        self.assertEqual(receipt["outcome"], "checks_failed")
        checks = self.by_name(receipt, "checks")
        self.assertEqual(checks["dns_a_fake_ip"]["status"], "fail")
        self.assertEqual(checks["fake_ip_tcp_echo"]["status"], "fail")
        self.assertEqual(checks["tcp4_echo"]["status"], "pass")
        self.assertIs(receipt["disconnect_verified"], True)
        self.assertIs(receipt["rollback_cancelled"], True)
        self.assert_rollback_exits(receipt)
        self.assertEqual(self.state()["status"], "Disconnected")
        self.assert_released(receipt)

    def test_anchor_or_out_of_pool_fake_ip_fails(self):
        for answer in ("198.19.255.2", "198.20.0.1", "198.18.0.256"):
            with self.subTest(answer=answer):
                (self.root / "state.json").unlink(missing_ok=True)
                result, receipt = self.run_harness({"dns_a": answer})
                self.assertEqual(result.returncode, 1)
                self.assertEqual(self.by_name(receipt, "checks")["dns_a_fake_ip"]["status"], "fail")

    def test_broken_echo_fails_only_that_check(self):
        result, receipt = self.run_harness({"broken_echo": ["2001:db8::10"]})
        self.assertEqual(result.returncode, 1)
        failed = [c["name"] for c in receipt["checks"] if c["status"] == "fail"]
        self.assertEqual(failed, ["tcp6_echo"])

    def test_connect_failure_runs_trap_cleanup(self):
        result, receipt = self.run_harness({"connect_exit": 2})
        self.assertEqual(result.returncode, 1)
        self.assertEqual(receipt["outcome"], "connect_failed")
        self.assertEqual(self.host_verbs(), ["--ping", "--list", "--connect", "--disconnect"])
        self.assertEqual(receipt["checks"], [])
        self.assertIs(receipt["disconnect_verified"], True)
        self.assertIs(receipt["rollback_cancelled"], True)
        self.assert_rollback_exits(receipt)
        self.assert_released(receipt)

    def test_unverified_disconnect_escalates_and_keeps_rollback_armed(self):
        result, receipt = self.run_harness({"stuck": True})
        self.assertEqual(result.returncode, 6, result.stdout)
        self.assertEqual(receipt["outcome"], "disconnect_unverified")
        self.assertNotIn("outcome_before_disconnect", receipt)
        self.assertTrue(all(c["status"] == "pass" for c in receipt["checks"]))
        self.assertIs(receipt["disconnect_verified"], False)
        self.assertIs(receipt["rollback_cancelled"], False)
        self.assertEqual(self.host_verbs(), ["--ping", "--list", "--connect", "--disconnect",
                                             "--emergency-stop"])
        self.assertIn(["--nc", "stop", SID], [c["args"] for c in self.calls() if c["tool"] == "scutil"])
        self.assertTrue(self.alive(receipt["rollback_pid"]))
        self.assertEqual(self.ps(receipt["rollback_pid"], "ppid"), "1")
        self.assertEqual(self.by_name(receipt, "rollback")["kept"]["status"], "pass")
        # The lock is not released while the tunnel state is unverified.
        self.assert_lock_kept(receipt, "rollback_pending")

    def test_unverified_disconnect_after_a_failure_keeps_the_earlier_outcome(self):
        result, receipt = self.run_harness({"stuck": True, "connect_exit": 2})
        self.assertEqual(result.returncode, 6)
        self.assertEqual(receipt["outcome"], "disconnect_unverified")
        self.assertEqual(receipt["outcome_before_disconnect"], "connect_failed")
        self.assertTrue(self.alive(receipt["rollback_pid"]))
        self.assert_lock_kept(receipt, "rollback_pending")

    def test_lingering_tunnel_address_is_not_a_verified_disconnect(self):
        result, receipt = self.run_harness({"lingering_address": True})
        self.assertEqual(result.returncode, 6)
        self.assertIs(receipt["rollback_cancelled"], False)
        self.assertTrue(self.alive(receipt["rollback_pid"]))
        self.assert_lock_kept(receipt, "rollback_pending")

    def test_unverified_disconnect_after_the_rollback_ran_keeps_the_lock_for_manual_release(self):
        # The rollback fires at once, cannot verify the stuck tunnel either and
        # finishes before the harness: nothing is left to release the lock.
        result, receipt = self.run_harness({"stuck": True}, "--rollback-seconds", "1")
        self.assertEqual(result.returncode, 6, result.stdout)
        log = (pathlib.Path(receipt["run_dir"]) / "rollback.log").read_text()
        self.assertIn("rollback_unverified\nrollback_lock_kept reason=unverified\nrollback_done\n", log)
        self.assertEqual(self.by_name(receipt, "rollback")["kept"]["status"], "fail")
        self.assert_lock_kept(receipt, "disconnect_unverified")
        self.assertIn("release=remove it by hand", (self.locks / "timing-self").read_text())

    def test_failed_host_disconnect_always_escalates(self):
        # The fake still disconnects but --disconnect exits 2, as when it fails
        # before stopVPNTunnel while the session is Connecting with no routes.
        code, receipt = self.interrupt_after_connect({"connect_result": "Connecting", "disconnect_exit": 2})
        self.assertEqual(code, 130)
        disconnect = self.by_name(receipt, "disconnect")
        self.assertEqual(disconnect["host_disconnect"]["status"], "fail")
        self.assertNotIn("verified_after_host_disconnect", disconnect)
        self.assertEqual(disconnect["verified_after_scutil_stop"]["status"], "pass")
        self.assertIn(["--nc", "stop", SID], [c["args"] for c in self.calls() if c["tool"] == "scutil"])
        self.assertIs(receipt["rollback_cancelled"], True)
        self.assert_released(receipt)

    def test_still_connecting_is_never_a_verified_disconnect(self):
        # Routes and addresses look physical while the session is Connecting.
        code, receipt = self.interrupt_after_connect(
            {"connect_result": "Connecting", "disconnect_works": False, "scutil_stop_works": False,
             "emergency_works": False})
        self.assertEqual(code, 6)
        self.assertEqual(receipt["outcome"], "disconnect_unverified")
        self.assertEqual(receipt["outcome_before_disconnect"], "interrupted")
        disconnect = self.by_name(receipt, "disconnect")
        for name in ("verified_after_host_disconnect", "verified_after_scutil_stop",
                     "verified_after_emergency_stop"):
            self.assertEqual(disconnect[name]["status"], "fail")
            self.assertIn("status=Connecting default_interface=en0 tunnel_interfaces=none",
                          disconnect[name]["detail"])
        self.assertIs(receipt["disconnect_verified"], False)
        self.assertTrue(self.alive(receipt["rollback_pid"]))
        self.assert_lock_kept(receipt, "rollback_pending")

    def test_disconnected_must_hold_on_two_polls_in_a_row(self):
        result, receipt = self.run_harness({"status_after_disconnect": ["Disconnected", "Connecting"]})
        self.assertEqual(result.returncode, 0, result.stdout)
        # Disconnected, Connecting (streak reset), Disconnected, Disconnected.
        self.assertEqual(len(self.status_calls_after_disconnect()), 4)
        self.assertEqual(self.by_name(receipt, "disconnect")["verified_after_host_disconnect"]["status"], "pass")

    def test_pending_rollback_refuses_a_new_window(self):
        result, receipt = self.run_harness({"stuck": True})
        self.assertEqual(result.returncode, 6)
        pending = receipt["rollback_pid"]
        # Even with its lock gone by hand, the live rollback blocks the next window.
        (self.locks / "timing-self").unlink()
        for path in ("calls.log", "state.json"):
            (self.root / path).unlink()
        result, again = self.run_harness({})
        self.assertEqual(result.returncode, 3, result.stderr)
        refused = [p for p in again["preconditions"] if p["status"] != "pass"]
        self.assertEqual([p["name"] for p in refused], ["no_pending_rollback"])
        self.assertIn("%d:" % pending, refused[0]["detail"])
        self.assertEqual(self.calls(), [])
        self.assertFalse((self.locks / "timing-self").exists())
        # Once it is gone, the window may run again.
        os.kill(pending, signal.SIGKILL)
        self.wait_for(lambda: not self.alive(pending))
        result, third = self.run_harness({})
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_lock_replaced_by_someone_else_is_not_removed(self):
        result, receipt = self.run_harness({"replace_own_lock": True})
        self.assertEqual(result.returncode, 0)
        self.assertIs(receipt["lock_removed"], False)
        self.assertEqual((self.locks / "timing-self").read_text(), "someone else\n")

    def test_lsof_unavailable_is_recorded_not_failed_and_a_wrong_socket_fails(self):
        result, receipt = self.run_harness({"lsof": "denied"})
        self.assertEqual(result.returncode, 0, result.stdout)
        relay = self.by_name(receipt, "checks")["relay_socket"]
        self.assertEqual(relay["status"], "unavailable")
        self.assertEqual(receipt["checks_unavailable"], 1)
        (self.root / "state.json").unlink()
        result, receipt = self.run_harness({"provider_pids": []})
        self.assertEqual(self.by_name(receipt, "checks")["relay_socket"]["status"], "unavailable")
        (self.root / "state.json").unlink()
        result, receipt = self.run_harness({"lsof": "other"})
        self.assertEqual(result.returncode, 1)
        self.assertEqual(self.by_name(receipt, "checks")["relay_socket"]["status"], "fail")

    def test_hard_timeout_terminates_and_cleans_up_within_the_bound(self):
        started = time.time()
        result, receipt = self.run_harness({"connect_result": "Connecting"}, "--hard-timeout", "20")
        elapsed = time.time() - started
        self.assertEqual(result.returncode, 5, result.stdout + result.stderr)
        self.assertEqual(receipt["outcome"], "hard_timeout")
        self.assertLess(elapsed, 20)
        self.assertGreaterEqual(receipt["elapsed_seconds"], 5)
        self.assertEqual(self.host_verbs()[-1], "--disconnect")
        self.assertIs(receipt["disconnect_verified"], True)
        self.assertIs(receipt["rollback_cancelled"], True)
        self.assertEqual(receipt["checks"], [])
        self.assertIn("signal", {e["kind"] for e in receipt["events"]})
        self.assert_released(receipt)

    def test_hard_timeout_with_stuck_tunnel_still_writes_the_receipt(self):
        started = time.time()
        result, receipt = self.run_harness(
            {"connect_result": "Connecting", "stuck": True,
             "hang_verbs": ["--disconnect", "--emergency-stop"]}, "--hard-timeout", "20", timeout=40)
        elapsed = time.time() - started
        self.assertEqual(result.returncode, 6, result.stdout + result.stderr)
        self.assertEqual(receipt["outcome"], "disconnect_unverified")
        self.assertEqual(receipt["outcome_before_disconnect"], "hard_timeout")
        self.assertLess(elapsed, 20)
        marker = (pathlib.Path(receipt["run_dir"]) / "hard-timeout").read_text()
        self.assertEqual(marker, "hard_timeout term\n")
        disconnect = self.by_name(receipt, "disconnect")
        self.assertIn("bounds=short", disconnect["stop_sequence"]["detail"])
        for name in ("host_disconnect", "emergency_stop"):
            self.assertEqual(disconnect[name]["status"], "fail")
        self.assertEqual(disconnect["scutil_stop"]["status"], "pass")
        self.assertIn("--emergency-stop", self.host_verbs())
        self.assertTrue(self.alive(receipt["rollback_pid"]))
        self.assert_lock_kept(receipt, "rollback_pending")

    def test_hung_disconnect_after_hard_timeout_still_escalates(self):
        result, receipt = self.run_harness({"connect_result": "Connecting", "hang_verbs": ["--disconnect"]},
                                           "--hard-timeout", "20", timeout=40)
        self.assertEqual(result.returncode, 5, result.stdout + result.stderr)
        disconnect = self.by_name(receipt, "disconnect")
        self.assertEqual(disconnect["host_disconnect"]["status"], "fail")
        self.assertIn("rc=142", disconnect["host_disconnect"]["detail"])
        self.assertEqual(disconnect["verified_after_scutil_stop"]["status"], "pass")
        self.assertIs(receipt["rollback_cancelled"], True)
        self.assert_released(receipt)

    def test_hung_command_is_bounded_and_trapped(self):
        result, receipt = self.run_harness({"hang": ["dig"]}, "--hard-timeout", "20", timeout=40)
        self.assertIn(result.returncode, (1, 5))
        self.assertIs(receipt["disconnect_verified"], True)
        self.assert_released(receipt)

    def test_sigint_runs_trap_cleanup(self):
        proc = self.start_harness({"connect_result": "Connecting"})
        try:
            self.wait_for(lambda: "--connect" in self.host_verbs())
            proc.send_signal(signal.SIGINT)
            stdout, _ = proc.communicate(timeout=30)
        finally:
            if proc.poll() is None:
                proc.kill()
        self.assertEqual(proc.returncode, 130)
        receipt = self.receipt(stdout)
        self.assertEqual(receipt["outcome"], "interrupted")
        self.assertEqual(self.host_verbs()[-1], "--disconnect")
        self.assertIs(receipt["disconnect_verified"], True)
        self.assertIs(receipt["rollback_cancelled"], True)
        self.assert_rollback_exits(receipt)
        self.assert_released(receipt)

    def test_sigterm_runs_trap_cleanup(self):
        proc = self.start_harness({"connect_result": "Connecting"})
        try:
            self.wait_for(lambda: "--connect" in self.host_verbs())
            proc.send_signal(signal.SIGTERM)
            stdout, _ = proc.communicate(timeout=30)
        finally:
            if proc.poll() is None:
                proc.kill()
        self.assertEqual(proc.returncode, 143)
        receipt = self.receipt(stdout)
        self.assertEqual(receipt["outcome"], "interrupted")
        self.assertEqual(self.state()["status"], "Disconnected")
        self.assert_released(receipt)

    def test_process_group_signal_does_not_reach_the_rollback(self):
        proc = self.start_harness({"connect_result": "Connecting", "stuck": True}, session=True)
        try:
            self.wait_for(lambda: "--connect" in self.host_verbs())
            os.killpg(proc.pid, signal.SIGTERM)
            stdout, _ = proc.communicate(timeout=60)
        finally:
            if proc.poll() is None:
                proc.kill()
        receipt = self.receipt(stdout)
        self.assertEqual(receipt["outcome"], "disconnect_unverified")
        self.assertTrue(self.alive(receipt["rollback_pid"]))
        self.assert_lock_kept(receipt, "rollback_pending")

    def test_detached_rollback_fires_stop_then_emergency_stop(self):
        result, receipt = self.run_harness({"connect_result": "Connecting"}, "--rollback-seconds", "1",
                                           "--hard-timeout", "20")
        self.assertEqual(result.returncode, 5)
        log = (pathlib.Path(receipt["run_dir"]) / "rollback.log").read_text()
        self.assertIn("rollback_fired", log)
        self.assertRegex(log, r"rollback_ran scutil --nc stop %s status=0" % SID)
        self.assertRegex(log, r"rollback_ran \S+aegis-ne-host --emergency-stop status=0")
        self.assertIn("--emergency-stop", self.host_verbs())
        # The fired rollback cannot be cancelled: it keeps the lock and releases
        # it itself once it observes Disconnected and the harness has exited.
        self.assertEqual(receipt["lock_kept_reason"], "rollback_running")
        # It waited for the harness to exit: the lock was still there at the end.
        kept = [e for e in receipt["events"] if e["kind"] == "lock" and e["name"] == "kept"]
        self.assertEqual([e["detail"] for e in kept],
                         ["rollback_running: the rollback removes it after it observes Disconnected"])
        log = pathlib.Path(receipt["run_dir"]) / "rollback.log"
        self.wait_for(lambda: "rollback_done" in log.read_text(), seconds=20)
        self.assertIn("rollback_observed status=Disconnected", log.read_text())
        self.assertIn("rollback_lock_released", log.read_text())
        self.assertFalse((self.locks / "timing-self").exists())

    def test_killed_harness_leaves_rollback_armed(self):
        proc = self.start_harness({"connect_result": "Connecting"}, "--rollback-seconds", "2")
        try:
            self.wait_for(lambda: "--connect" in self.host_verbs())
            proc.kill()
            proc.communicate(timeout=10)
        finally:
            if proc.poll() is None:
                proc.kill()
        log = next(self.artifacts.glob("*/rollback.log"))
        self.wait_for(lambda: "rollback_done" in log.read_text(), seconds=30)
        self.assertEqual(self.state()["status"], "Disconnected")
        # The rollback, not the dead harness, released the timing lock.
        self.assertIn("rollback_lock_released", log.read_text())
        self.assertFalse((self.locks / "timing-self").exists())
        # The provisional receipt was written before --connect.
        receipt = json.loads(next(self.artifacts.glob("*/receipt.json")).read_text())
        self.assertEqual(receipt["outcome"], "in_progress")
        self.assertEqual(receipt["service_id"], SID)
        # The orphaned watchdog notices its parent is gone and never signals.
        watchdog = int(next(self.artifacts.glob("*/watchdog.pid")).read_text())
        self.wait_for(lambda: not self.alive(watchdog), seconds=5)
        self.assertFalse(next(self.artifacts.glob("*/")).joinpath("hard-timeout").exists())

    def test_rollback_is_outside_the_harness_process_tree(self):
        proc = self.start_harness({"connect_result": "Connecting"}, "--rollback-seconds", "5")
        try:
            self.wait_for(lambda: "--connect" in self.host_verbs())
            rollback = self.rollback_pid()
            self.assertEqual(self.ps(rollback, "ppid"), "1")
            self.assertEqual(self.ps(rollback, "pgid"), str(rollback))
            tree = self.descendants(proc.pid)
            self.assertNotIn(rollback, tree)
            # Signals a runner would send to the tree do not stop it.
            for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
                os.kill(rollback, sig)
            time.sleep(0.3)
            self.assertTrue(self.alive(rollback))
            # A descendant-walking SIGKILL (harness, watchdog, current step).
            for pid in [proc.pid] + tree:
                try:
                    os.kill(pid, signal.SIGKILL)
                except OSError:
                    pass
            proc.communicate(timeout=10)
        finally:
            if proc.poll() is None:
                proc.kill()
        self.assertTrue(self.alive(rollback))
        log = self.rollback_log()
        self.wait_for(lambda: "rollback_done" in log.read_text(), seconds=30)
        text = log.read_text()
        self.assertIn("rollback_fired", text)
        self.assertIn("rollback_lock_released", text)
        self.assertEqual(self.state()["status"], "Disconnected")
        self.assertFalse((self.locks / "timing-self").exists())

    def test_failed_runs_are_kept_under_unique_names(self):
        first, one = self.run_harness({"relay_listening": False})
        second, two = self.run_harness({"relay_listening": False})
        self.assertEqual((first.returncode, second.returncode), (3, 3))
        self.assertNotEqual(one["run_dir"], two["run_dir"])
        for receipt in (one, two):
            self.assertTrue(pathlib.Path(receipt["run_dir"], "receipt.json").exists())
            self.assertTrue(pathlib.Path(receipt["run_dir"]).is_relative_to(self.artifacts))


class RollbackTests(HarnessFixture):
    def run_rollback(self, cancel_text, lock_text):
        body = re.search(r"^ROLLBACK_PERL='(.*?)^'$", HARNESS.read_text(), re.M | re.S).group(1)
        (self.root / "scenario.json").write_text("{}")
        cancel, lock, log = self.root / "rollback.cancel", self.root / "lock", self.root / "rollback.log"
        cancel.write_text(cancel_text)
        lock.write_text(lock_text)
        gone = subprocess.Popen(["true"])
        gone.wait()
        host = self.app / "Contents" / "MacOS" / "aegis-ne-host"
        with open(log, "w") as handle:
            subprocess.run(["perl", "-e", body, "1", str(int(time.time()) + 100), SID, str(host), str(cancel),
                            str(lock), "owner=claude pid=1 run=r", "198.19.255.1", str(gone.pid)],
                           env=self.env(), stdout=handle, stderr=subprocess.STDOUT, timeout=10, check=True)
        self.wait_for(lambda: "rollback_armed pid=" in log.read_text())
        pid = int(re.search(r"^rollback_armed pid=(\d+)", log.read_text(), re.M).group(1))
        self.wait_for(lambda: not self.alive(pid), seconds=30)
        return log.read_text(), lock.exists()

    def test_another_token_neither_cancels_nor_releases(self):
        log, lock_left = self.run_rollback("owner=claude pid=2 run=other\n", "owner=claude pid=2 run=other\n")
        self.assertNotIn("rollback_cancelled", log)
        self.assertIn("rollback_fired", log)
        self.assertIn("rollback_ran scutil --nc stop %s status=0" % SID, log)
        self.assertIn("rollback_lock_kept reason=not_ours\nrollback_done\n", log)
        self.assertTrue(lock_left)

    def test_its_own_token_cancels_and_releases_its_lock(self):
        log, lock_left = self.run_rollback("owner=claude pid=1 run=r\n", "started=x\nowner=claude pid=1 run=r\n")
        self.assertNotIn("rollback_fired", log)
        self.assertTrue(log.endswith("rollback_cancelled\nrollback_lock_released\n"), log)
        self.assertFalse(lock_left)
        self.assertEqual(self.calls(), [])


class WatchdogTests(HarnessFixture):
    def watchdog_kill(self, rollback_text, settled):
        script = HARNESS.read_text()
        body = re.search(r"^WATCHDOG_PERL='(.*?)^'$", script, re.M | re.S).group(1)
        marker, lock, log = self.root / "marker", self.root / "lock", self.root / "rollback.log"
        token = "owner=claude pid=1 run=x"
        lock.write_text("started=now\n%s\n" % token)
        if rollback_text is not None:
            log.write_text(rollback_text)
        # A parent that ignores the TERM, so only the KILL ends it.
        subprocess.run(["/bin/bash", "-c", 'trap "" TERM; perl -e "$1" 1 1 $$ "$2" "$3" "$4" "$5" & sleep 10',
                        "watchdog", body, str(marker), str(lock), token, str(log)],
                       timeout=20, check=False)
        # The watchdog finishes just after its KILL ends the parent.
        self.wait_for(lambda: marker.exists() and settled(marker.read_text(), lock.exists()), seconds=5)
        time.sleep(0.3)
        return marker.read_text(), lock.exists()

    def test_watchdog_kill_leaves_the_lock_to_an_armed_rollback(self):
        marker, lock_left = self.watchdog_kill("rollback_armed pid=1 seconds=90 fires_at_epoch=1\n",
                                               lambda text, _: "lock_left_to_rollback" in text)
        self.assertEqual(marker, "hard_timeout term\nhard_timeout kill\nlock_left_to_rollback\n")
        self.assertTrue(lock_left)

    def test_watchdog_kill_removes_its_lock_when_no_rollback_was_armed(self):
        marker, lock_left = self.watchdog_kill(None, lambda text, exists: "kill" in text and not exists)
        self.assertEqual(marker, "hard_timeout term\nhard_timeout kill\n")
        self.assertFalse(lock_left)


class ChecksOnlyTests(HarnessFixture):
    def test_checks_only_never_connects_disconnects_or_arms_rollback(self):
        result, receipt = self.run_harness({"initially_connected": True}, "--checks-only")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(receipt["mode"], "checks-only")
        self.assertEqual(self.host_verbs(), ["--ping", "--list"])
        self.assertNotIn("rollback_pid", receipt)
        self.assertNotIn("disconnect_verified", receipt)
        self.assertTrue(all(c["status"] == "pass" for c in receipt["checks"]))
        self.assertEqual(self.state()["status"], "Connected")
        self.assert_released(receipt)

    def test_checks_only_refuses_when_not_connected(self):
        result, receipt = self.run_harness({}, "--checks-only")
        self.assertEqual(result.returncode, 3)
        self.assertEqual(receipt["preconditions"][-1]["name"], "tunnel_connected")


if __name__ == "__main__":
    unittest.main()
