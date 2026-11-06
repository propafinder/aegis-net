"""Root Linux kernel regression: the bound scoped reply must survive srcnat.

The v2 guard postroute chain runs at srcnat + 10. By then the NAT core has
rewritten a redirected listener's reply source to the original target, so a
postroute rule that repeats OUTPUT's header tuple can never match (r15 #36).
Everything here runs inside two UNNAMED network namespaces joined by a veth:
the committed render() output (listener cgroup = this test's own cgroup) and
the product scoped redirect script are loaded there, never in the init
namespace, never under /run/netns. Linux and euid 0 only; elsewhere it skips.
"""
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
import unittest

TESTS = Path(__file__).resolve().parent
sys.path.insert(0, str(TESTS.parent / "lib"))
sys.path.insert(0, str(TESTS))

import auto_guard_render_harness as harness  # noqa: E402
import aegis_auto_guard_policy as policy  # noqa: E402
from aegis_auto_native_witness import policy_projection  # noqa: E402

ROOT_LINUX = sys.platform.startswith("linux") and os.geteuid() == 0
NSENTER = "/usr/bin/nsenter"
UNSHARE = "/usr/bin/unshare"
NFT = "/usr/sbin/nft"
IP = "/usr/sbin/ip"
PYTHON = "/usr/bin/python3"
LISTEN = "10.231.99.1"
PEER = "10.231.99.2"
TARGET = "192.0.2.251"
TARGET_PORT = 18080
SERVER_IF = "aegisnat0"
PEER_IF = "aegisnat1"
UPLINK = "aegisup0"
BOOT = "11111111-2222-3333-4444-555555555555"
STATE = (b"schema=aegis_device_guard_v2\narmed=1\nservice=aegis-client.service\n"
         b"uplink=" + UPLINK.encode() + b"\nmanager=systemd-networkd.service\n"
         b"capture_interface=aegis-tun0\ncapture_profile=wide-redirect-safe\n"
         b"management_address_policy=current_local\nmanagement_ports=22\n"
         b"dhcp4=0\ndhcp6=0\ninitramfs_network=absent_verified\n")
LISTENER = r"""
import socket,sys
s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind((sys.argv[1],int(sys.argv[2]))); s.listen(4); s.settimeout(6)
print('ready',flush=True)
try:
    c,_=s.accept(); c.settimeout(4); data=c.recv(8); c.sendall(data); c.close()
    print('accepted',flush=True)
except OSError as e:
    print('listener',type(e).__name__,flush=True)
"""
CLIENT = r"""
import socket,sys,time
t=time.monotonic()
try:
    c=socket.create_connection((sys.argv[1],int(sys.argv[2])),timeout=4)
    c.sendall(b'aegis-36'); data=c.recv(8); c.close()
    print('connected' if data==b'aegis-36' else 'short', round(time.monotonic()-t,3))
except OSError as e:
    print(type(e).__name__, round(time.monotonic()-t,3))
"""
IN_NS = ("import os;a=os.stat('/proc/self/ns/net').st_ino;"
         "b=os.stat('/proc/1/ns/net').st_ino;print(int(a!=b),a)")


def init_netns() -> int:
    return os.stat("/proc/1/ns/net").st_ino


class Namespace:
    """One unnamed network namespace held by a sleeping child."""

    def __init__(self):
        own = os.stat("/proc/self/ns/net").st_ino
        self.child = subprocess.Popen([UNSHARE, "-n", "/bin/sleep", "120"],
                                      stdin=subprocess.DEVNULL)
        self.pid = self.child.pid
        until = time.monotonic() + 5
        while time.monotonic() < until:
            try:
                inode = os.stat(f"/proc/{self.pid}/ns/net").st_ino
            except FileNotFoundError:
                inode = own
            if inode != own:
                break
            time.sleep(0.02)
        self.inode = os.stat(f"/proc/{self.pid}/ns/net").st_ino
        if self.inode in (own, init_netns()):
            self.close()
            raise AssertionError("unnamed_netns_not_entered")
        proof = self.run([PYTHON, "-I", "-c", IN_NS]).split()
        if proof != ["1", str(self.inode)]:
            self.close()
            raise AssertionError("unnamed_netns_not_entered")

    def argv(self, argv):
        # Every command re-proves the target namespace is not the host's.
        if os.stat(f"/proc/{self.pid}/ns/net").st_ino != self.inode or \
                self.inode == init_netns():
            raise AssertionError("netns_identity_changed")
        return [NSENTER, "-t", str(self.pid), "-n", *argv]

    def run(self, argv, data=None, timeout=15, check=True):
        done = subprocess.run(self.argv(argv), input=data, capture_output=True,
                              timeout=timeout, stdin=None if data is not None
                              else subprocess.DEVNULL)
        if check and done.returncode:
            raise AssertionError("netns_command_failed:" + Path(argv[0]).name + ":" +
                                 done.stderr.decode(errors="replace")[-300:])
        return done.stdout.decode()

    def close(self):
        if self.child.poll() is None:
            self.child.send_signal(signal.SIGKILL)
        self.child.wait(timeout=10)


def own_cgroup() -> str:
    lines = [line for line in Path("/proc/self/cgroup").read_text().splitlines()
             if line.startswith("0::/")]
    if len(lines) != 1 or lines[0] == "0::/":
        raise AssertionError("cgroup2_leaf_required")
    return lines[0][4:]


def scoped_binding(ifindex: int, netns: int) -> dict:
    binding = {"stage_dev": 11, "stage_ino": 12,
               "private_unit": "aegis-auto@" + "a" * 64 + ".service",
               "transaction_nonce": "b" * 32, "planned_generation": "c" * 64,
               "boot_id": BOOT, "netns_ino": netns,
               "config_sha256_initial": "d" * 64, "config_semantic_sha256": "e" * 64,
               "interface": SERVER_IF, "ifindex": ifindex, "listen_ipv4": LISTEN,
               "listen_port": 15080, "guard_policy_sha256": "f" * 64}
    return policy._scoped_binding(binding, check_host=False)


def client_binding() -> dict:
    return {"schema": "aegis_device_guard_binding_v1", "boot_id": BOOT,
            "state_sha256": hashlib.sha256(STATE.rstrip(b"\n")).hexdigest(),
            "path": own_cgroup(), "inode": "1234", "invocation": "a" * 32}


def scoped_reply(binding: dict, client: dict, mark: int | None = None) -> dict:
    material = {"binding": binding,
                "client": {key: client[key] for key in ("path", "inode", "invocation")}}
    _owner, scoped_mark = policy._scoped_marker(binding)
    return {"binding": binding, "mark": scoped_mark if mark is None else mark,
            "marker": "aegis-auto-scoped-reply-" +
            hashlib.sha256(policy._scoped_json(material)).hexdigest()}


def verbatim_mirror(rendered: str, marker: str) -> str:
    """The pre-fix shape: each scoped postroute rule repeats OUTPUT's text."""
    lines = rendered.splitlines()
    outputs = [line for line in lines if line.split()[4:5] == ["output"]
               and line.endswith(f'comment "{marker}"')]
    posts = [index for index, line in enumerate(lines)
             if line.split()[4:5] == ["postroute"] and line.endswith(f'comment "{marker}"')]
    if len(outputs) != 3 or len(posts) != 3:
        raise AssertionError("scoped_rule_inventory_changed")
    for index, line in zip(posts, outputs):
        fields = line.split()
        fields[4] = "postroute"
        lines[index] = " ".join(fields)
    return "\n".join(lines) + "\n"


@unittest.skipUnless(ROOT_LINUX, "root Linux kernel regression")
class ScopedReplySurvivesSrcnat(unittest.TestCase):
    def setUp(self):
        self.spaces = []
        self.init_ruleset = subprocess.run([NFT, "--json", "list", "ruleset"],
                                           capture_output=True, timeout=15,
                                           check=True).stdout

    def tearDown(self):
        for space in self.spaces:
            space.close()
        self.assertEqual(self.init_ruleset, subprocess.run(
            [NFT, "--json", "list", "ruleset"], capture_output=True, timeout=15,
            check=True).stdout, "init netns ruleset changed")

    def pair(self):
        server, peer = Namespace(), Namespace()
        self.spaces += [server, peer]
        server.run([IP, "link", "add", SERVER_IF, "type", "veth", "peer", "name", PEER_IF])
        server.run([IP, "link", "set", PEER_IF, "netns", str(peer.pid)])
        for space, name, address in ((server, SERVER_IF, LISTEN), (peer, PEER_IF, PEER)):
            space.run([IP, "link", "set", "lo", "up"])
            space.run([IP, "address", "add", address + "/30", "dev", name])
            space.run([IP, "link", "set", name, "up"])
        peer.run([IP, "route", "add", "192.0.2.0/24", "via", LISTEN])
        ifindex = json.loads(server.run([IP, "-j", "link", "show", "dev", SERVER_IF]))[0]["ifindex"]
        return server, peer, ifindex

    def render(self, client, scoped):
        code, out, err = harness.render(profile="wide-redirect-safe", uplink=UPLINK,
                                        management_ports="22", client=client,
                                        scoped=scoped)
        self.assertEqual((0, ""), (code, err))
        self.assertNotIn(harness.REFUSED, out)
        return out

    def scoped_counters(self, server, marker):
        rows = json.loads(server.run([NFT, "--json", "list", "table", "inet",
                                      harness.TABLE]))["nftables"]
        counts = {"output": [], "postroute": []}
        for row in rows:
            rule = row.get("rule")
            if rule and rule.get("comment") == marker:
                packets = [item["counter"]["packets"] for item in rule["expr"]
                           if "counter" in item]
                counts[rule["chain"]].append(packets[0])
        self.assertEqual([3, 3], [len(counts["output"]), len(counts["postroute"])])
        return counts

    def attempt(self, guard_text, binding, redirect_mark=None):
        server, peer, _ifindex = self.current
        server.run([NFT, "-f", "-"], data=guard_text.encode())
        server.run([NFT, "-f", "-"], data=policy._scoped_script(binding, active=False))
        active = policy._scoped_script(binding, active=True).decode()
        if redirect_mark is not None:
            _owner, mark = policy._scoped_marker(binding)
            active = harness.replace_once(active, f"ct mark set 0x{mark:08x}",
                                          f"ct mark set 0x{redirect_mark:08x}")
        server.run([NFT, "-f", "-"], data=active.encode())
        listener = subprocess.Popen(server.argv([PYTHON, "-I", "-c", LISTENER, LISTEN, "15080"]),
                                    stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                    stderr=subprocess.DEVNULL, text=True)
        try:
            self.assertEqual("ready", listener.stdout.readline().strip())
            result = peer.run([PYTHON, "-I", "-c", CLIENT, TARGET, str(TARGET_PORT)],
                              timeout=15).split()
        finally:
            try:
                listener.wait(timeout=10)
            except subprocess.TimeoutExpired:
                listener.kill()
                listener.wait(timeout=5)
            listener.stdout.close()
        return result[0]

    def fresh(self, client):
        self.current = self.pair()
        server, _peer, ifindex = self.current
        binding = scoped_binding(ifindex, server.inode)
        return binding, scoped_reply(binding, client)

    def test_bound_scoped_reply_completes_handshake_and_reads_back_exactly(self):
        client = client_binding()
        binding, scoped = self.fresh(client)
        rendered = self.render(client, scoped)
        self.assertEqual("connected", self.attempt(rendered, binding))
        server = self.current[0]
        counts = self.scoped_counters(server, scoped["marker"])
        self.assertGreaterEqual(counts["output"][0], 1)
        self.assertGreaterEqual(counts["postroute"][0], 1)
        raw = server.run([NFT, "--json", "--handle", "list", "table", "inet",
                          harness.TABLE]).encode()
        text = server.run([NFT, "-a", "list", "table", "inet", harness.TABLE]).encode()
        projection, _handles, _counters = policy_projection(raw)
        actual, _chains = policy._canonical_rules(projection)
        state = policy.parse_state(STATE)
        expected = policy._expected(state, client, None, scoped, ())
        policy._text_binding_levels(text, raw, expected)
        self.assertEqual(policy._expected_with_elided_levels(expected, actual), actual)

    def test_prefix_verbatim_mirror_times_out_after_output_accept(self):
        client = client_binding()
        binding, scoped = self.fresh(client)
        old = verbatim_mirror(self.render(client, scoped), scoped["marker"])
        self.assertEqual("TimeoutError", self.attempt(old, binding))
        counts = self.scoped_counters(self.current[0], scoped["marker"])
        self.assertGreater(counts["output"][0], 0)
        self.assertEqual(0, counts["postroute"][0])

    def test_redirect_with_other_conntrack_mark_times_out(self):
        client = client_binding()
        binding, scoped = self.fresh(client)
        self.assertEqual("TimeoutError", self.attempt(
            self.render(client, scoped), binding, redirect_mark=scoped["mark"] ^ 1))

    def test_guard_with_other_conntrack_mark_times_out(self):
        client = client_binding()
        binding, scoped = self.fresh(client)
        other = dict(scoped, mark=scoped["mark"] ^ 1)
        self.assertEqual("TimeoutError", self.attempt(self.render(client, other), binding))
        counts = self.scoped_counters(self.current[0], scoped["marker"])
        self.assertEqual([0, 0], [counts["output"][0], counts["postroute"][0]])

    def test_unpaired_twin_sentinel_is_refused_by_nft_check(self):
        client = client_binding()
        _binding, scoped = self.fresh(client)
        twins = [line for line in harness.render_function().splitlines(keepends=True)
                 if "printf 'postroute-only " in line and "rst == rst" in line]
        self.assertEqual(1, len(twins))
        code, out, err = harness.render(
            profile="wide-redirect-safe", uplink=UPLINK, management_ports="22",
            client=client, scoped=scoped, mutate=(twins[0], ""))
        self.assertEqual((0, ""), (code, err))
        self.assertEqual(1, out.splitlines().count(harness.REFUSED))
        server = self.current[0]
        done = subprocess.run(server.argv([NFT, "--check", "-f", "-"]), input=out.encode(),
                              capture_output=True, timeout=15)
        self.assertNotEqual(0, done.returncode)
        self.assertEqual("", server.run([NFT, "list", "ruleset"]))


if __name__ == "__main__":
    unittest.main()
