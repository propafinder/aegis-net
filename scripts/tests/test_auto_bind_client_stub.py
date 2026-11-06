"""S11: the guard helper's inline FD8 BIND client equals the guardian's.

The private ControlPID used to run `python3 -I -B aegis_auto_guardian.py
bind-foreign-assess|bind-seal 8`, which compiles the whole guardian for each
request (G0a on r17c: +61.8 ms per spawn). The installed guard helper, whose
digest the guardian install receipt pins, now carries the same client. These
fixtures drive both clients against one recording fake host guardian and
require identical requests and identical acceptance or refusal.
"""
import array
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "aegis-device-egress-guard.sh"
GUARDIAN = ROOT / "lib" / "aegis_auto_guardian.py"
BOOT = "/proc/sys/kernel/random/boot_id"
UNIT = "aegis-auto@" + "a" * 64 + ".service"
INVOCATION = "c" * 32
BOOT_ID = "0123abcd-0000-4000-8000-00000000beef"
PYTHON = sys.executable


def stub_source() -> str:
    text = HELPER.read_text(encoding="utf-8")
    match = re.search(r"<<'PY_BIND_CLIENT'\n(.*?)\nPY_BIND_CLIENT\n", text, re.S)
    assert match is not None
    return match.group(1) + "\n"


def guardian_runner() -> str:
    return (
        "import importlib.util,pathlib,sys\n"
        "real=pathlib.Path.read_text\n"
        "def read_text(self,*a,**k):\n"
        f" return real(pathlib.Path(sys.argv[3]),*a,**k) if str(self)=={BOOT!r} else real(self,*a,**k)\n"
        "pathlib.Path.read_text=read_text\n"
        "spec=importlib.util.spec_from_file_location('guardian_client_reference',sys.argv[1])\n"
        "module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)\n"
        "module.bind_seal_client(8,foreign_only=sys.argv[2]=='bind-foreign-assess')\n")


class StaticShape(unittest.TestCase):
    def test_helper_runs_the_inline_client_not_a_guardian_compile(self):
        text = HELPER.read_text(encoding="utf-8")
        self.assertEqual(text.count("<<'PY_BIND_CLIENT'"), 1)
        self.assertIn("    private_bind_client bind-foreign-assess || rc=$?\n", text)
        self.assertIn("    private_bind_client bind-seal ||\n"
                      "      fail 'private bind host semantic seal refused'\n", text)
        self.assertNotRegex(text, r'"\$AUTO_GUARDIAN" bind-(seal|foreign-assess)')
        # The guardian keeps its own client entry points unchanged.
        guardian = GUARDIAN.read_text(encoding="utf-8")
        self.assertIn('elif sys.argv == [str(SOURCE), "bind-seal", "8"]:', guardian)
        self.assertIn('elif sys.argv == [str(SOURCE), "bind-foreign-assess", "8"]:', guardian)

    def test_stub_keeps_the_guardian_client_constants_and_deadline(self):
        source = stub_source()
        guardian = GUARDIAN.read_text(encoding="utf-8")
        for constant in ('MAX_REQUEST = 8192', 'HEX64 = re.compile(r"[0-9a-f]{64}\\Z")',
                         'HEX32 = re.compile(r"[0-9a-f]{32}\\Z")',
                         'PRIVATE_UNIT = re.compile(r"aegis-auto@[0-9a-f]{64}\\.service\\Z")',
                         "deadline = time.monotonic() + 7"):
            self.assertIn(constant, guardian)
            self.assertIn(constant.replace(" = ", "=").replace(" + ", "+"), source)
        self.assertEqual(source.count(BOOT), 1)
        self.assertEqual(source.count("bind_seal_client(8,foreign_only="), 1)

    def test_stub_refuses_any_other_command(self):
        for argv in ([], ["seal-policy"], ["bind-seal", "8"], ["BIND-SEAL"]):
            with self.subTest(argv=argv):
                result = subprocess.run([PYTHON, "-I", "-B", "-", *argv],
                                        input=stub_source().encode(), capture_output=True,
                                        timeout=30, env={"PATH": "/usr/bin:/bin"})
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(b"fixed_bind_client_command_required", result.stderr)


@unittest.skipUnless(sys.platform.startswith("linux") and hasattr(socket, "SOCK_SEQPACKET"),
                     "Linux AF_UNIX SOCK_SEQPACKET channel")
class SameClientBehaviour(unittest.TestCase):
    def run_client(self, kind, command, reply_for, *, env=None, channel=socket.SOCK_SEQPACKET):
        with tempfile.TemporaryDirectory() as temporary:
            boot = Path(temporary) / "boot_id"
            boot.write_text(BOOT_ID + "\n", encoding="ascii")
            if kind == "stub":
                argv = [PYTHON, "-I", "-B", "-", command]
                program = stub_source().replace(BOOT, str(boot)).encode()
            else:
                argv = [PYTHON, "-I", "-B", "-c", guardian_runner(), str(GUARDIAN), command,
                        str(boot)]
                program = None
            host, client = socket.socketpair(socket.AF_UNIX, channel)
            with host, client:
                environment = {"PATH": "/usr/bin:/bin", "AEGIS_AUTO_PRIVATE_UNIT": UNIT,
                               "INVOCATION_ID": INVOCATION}
                environment.update(env or {})
                fd = client.fileno()
                # The helper's ControlPID inherits the channel as FD8 exactly.
                child = subprocess.Popen(
                    ["/bin/sh", "-c", f'exec 8<&{fd} {fd}<&-; exec "$@"', "sh", *argv],
                    stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE, env=environment, pass_fds=(fd,))
                client.close()
                host.settimeout(20)
                if program is not None:
                    child.stdin.write(program)
                child.stdin.close()
                request = None
                try:
                    # An exiting client closes FD8: EOF is "no request".
                    request = host.recv(65536) or None
                except (socket.timeout, OSError):
                    pass
                if request is not None:
                    payload, fds = reply_for(json.loads(request))
                    if fds:
                        host.sendmsg([payload], [(socket.SOL_SOCKET, socket.SCM_RIGHTS,
                                                  array.array("i", fds).tobytes())])
                    else:
                        host.send(payload)
                try:
                    child.wait(timeout=30)
                finally:
                    if child.poll() is None:
                        child.kill()
                        child.wait()
                err = child.stderr.read()
                child.stdout.close()
                child.stderr.close()
                return child.returncode, request, err

    def compare(self, command, reply_for, **options):
        stub = self.run_client("stub", command, reply_for, **options)
        reference = self.run_client("guardian", command, reply_for, **options)
        self.assertEqual(stub[1], reference[1], "identical request bytes")
        self.assertEqual(stub[0] == 0, reference[0] == 0, (stub[2][-400:], reference[2][-400:]))
        reason = re.findall(rb"Refused: ([a-z_]+)", reference[2])
        if reason:
            self.assertIn(reason[-1], stub[2])
        return stub

    @staticmethod
    def ack(command, **change):
        foreign = command == "bind-foreign-assess"
        value = {"schema": "aegis_auto_guardian_foreign_assessed_v1" if foreign else
                 "aegis_auto_guardian_bind_sealed_v1", "unit": UNIT, "boot_id": BOOT_ID,
                 "invocation_id": INVOCATION,
                 ("foreign_projection_sha256" if foreign else "policy_sha256"): "d" * 64}
        for key, item in change.items():
            if item is None:
                value.pop(key)
            else:
                value[key] = item
        return value

    def test_requests_and_valid_acks_are_identical(self):
        for command in ("bind-foreign-assess", "bind-seal"):
            with self.subTest(command=command):
                code, request, _ = self.compare(
                    command, lambda request, c=command: (json.dumps(self.ack(c)).encode(), ()))
                self.assertEqual(code, 0)
                foreign = command == "bind-foreign-assess"
                self.assertEqual(json.loads(request), {
                    "schema": "aegis_auto_guardian_bind_foreign_v1" if foreign else
                    "aegis_auto_guardian_bind_seal_v1",
                    "command": "BIND_FOREIGN_ASSESS" if foreign else "BIND_SEAL",
                    "unit": UNIT, "boot_id": BOOT_ID, "invocation_id": INVOCATION})

    def test_every_invalid_ack_is_refused_by_both(self):
        for command in ("bind-foreign-assess", "bind-seal"):
            field = "foreign_projection_sha256" if command == "bind-foreign-assess" else "policy_sha256"
            other = "policy_sha256" if field != "policy_sha256" else "foreign_projection_sha256"
            bad = [self.ack(command, schema="aegis_auto_guardian_bind_sealed_v2"),
                   self.ack(command, unit="aegis-auto@" + "b" * 64 + ".service"),
                   self.ack(command, boot_id="0123abcd-0000-4000-8000-00000000beee"),
                   self.ack(command, invocation_id="d" * 32),
                   self.ack(command, **{field: "D" * 64}),
                   self.ack(command, **{field: "d" * 63}),
                   self.ack(command, **{field: None}),
                   self.ack(command, **{other: "d" * 64}),
                   self.ack(command, extra="x")]
            for value in bad:
                with self.subTest(command=command, value=value):
                    code, _, _ = self.compare(
                        command, lambda request, v=value: (json.dumps(v).encode(), ()))
                    self.assertNotEqual(code, 0)
            raw = json.dumps(self.ack(command)).encode()
            duplicate = raw[:-1] + b',"unit":"' + UNIT.encode() + b'"}'
            for payload in (duplicate, b"[]", b"not json", b""):
                with self.subTest(command=command, payload=payload):
                    code, _, _ = self.compare(command, lambda request, p=payload: (p, ()))
                    self.assertNotEqual(code, 0)

    def test_an_ack_carrying_descriptors_is_refused_by_both(self):
        for command in ("bind-foreign-assess", "bind-seal"):
            with self.subTest(command=command):
                with open(os.devnull, "rb") as extra:
                    code, _, err = self.compare(
                        command, lambda request, c=command, f=extra.fileno():
                        (json.dumps(self.ack(c)).encode(), (f,)))
                self.assertNotEqual(code, 0)
                self.assertIn(b"unexpected_lease_ancillary_or_truncation", err)

    def test_identity_and_channel_refusals_precede_any_request(self):
        never = lambda request: self.fail("no request may be sent")  # noqa: E731
        for env in ({"AEGIS_AUTO_PRIVATE_UNIT": "aegis-client.service"},
                    {"AEGIS_AUTO_PRIVATE_UNIT": UNIT + "x"},
                    {"INVOCATION_ID": "C" * 32}, {"INVOCATION_ID": "c" * 31}):
            with self.subTest(env=env):
                code, request, err = self.compare("bind-seal", never, env=env)
                self.assertNotEqual(code, 0)
                self.assertIsNone(request)
                self.assertIn(b"bind_seal_identity_invalid", err)
        code, request, err = self.compare("bind-seal", never, channel=socket.SOCK_STREAM)
        self.assertNotEqual(code, 0)
        self.assertIsNone(request)
        self.assertIn(b"bind_seal_channel_invalid", err)


if __name__ == "__main__":
    unittest.main()
