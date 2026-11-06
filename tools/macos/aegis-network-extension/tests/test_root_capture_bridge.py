"""Inert privilege grammar controls. No root launch, capture or tunnel."""

import importlib.util
import os
from pathlib import Path
import signal
import socket
import subprocess
import threading
import tempfile
import unittest
from unittest import mock

SOURCE = Path(__file__).parents[1] / "harness" / "root_capture_bridge.py"
spec = importlib.util.spec_from_file_location("root_capture_bridge", SOURCE)
bridge = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bridge)
OUT = Path("/private/tmp/aegis-b06-s20-test")


def server(uid=None):
    _, _, sec, usec = bridge.process_identity(os.getpid())
    return bridge.CaptureServer(OUT / "bridge.sock", OUT, os.getuid() if uid is None else uid,
                                300, os.getpid(), (sec, usec), os.getpid(), (sec, usec),
                                "en0", ["en0"], SOURCE, "0" * 64, "0" * 64)


def capture(dev="en0", name="physical.pcap", bound="240"):
    return [bridge.TCPDUMP, "-i", dev, "-p", "-s", "160", "-B", "4096",
            "-G", bound, "-W", "1", "-U", "-w", str(OUT / name)]


class CaptureGrammar(unittest.TestCase):
    def test_primary_exact_and_independent_deadline(self):
        dev, name, end = bridge.capture_argv(capture(), OUT, 100, 500)
        self.assertEqual((dev, name, end), ("en0", str(OUT / "physical.pcap"), 345))
        self.assertEqual(bridge.capture_argv(
            [bridge.PERL, "-e", bridge.ALARM_PL, "270"] + capture("en7", "physical-en7.pcap"),
            OUT, 100, 500)[2], 375)
        self.assertEqual(bridge.root_capture_command("en0", "240"),
                         [bridge.PERL, "-e", bridge.ALARM_PL, "270", bridge.TCPDUMP,
                          "-i", "en0", "-p", "-s", "160", "-B", "4096", "-G", "240",
                          "-W", "1", "-U", "-w", "-"])

    def test_rejects_arbitrary_root_program_or_extra_flags(self):
        for args in (["/bin/sh", "-c", "id"],
                     capture() + ["-z", "/bin/sh"],
                     [bridge.PERL, "-e", "exec '/bin/sh'", "270"] + capture(),
                     [bridge.PERL, "-e", bridge.ALARM_PL, "271"] + capture()):
            with self.subTest(args=args), self.assertRaises(ValueError):
                bridge.capture_argv(args, OUT, 100, 500)

    def test_rejects_write_escape_and_unbounded_capture(self):
        for args in (capture(name="../outside.pcap"), capture(name="physical-en1.pcap"),
                     capture(dev="en0;id"), capture(bound="661"), capture(bound="0")):
            with self.subTest(args=args), self.assertRaises(ValueError):
                bridge.capture_argv(args, OUT, 100, 500)

    def test_refuses_near_root_server_deadline(self):
        with self.assertRaisesRegex(ValueError, "server_deadline"):
            bridge.capture_argv(capture(), OUT, 470, 500)

    def test_darwin_peer_uid_is_bound_to_local_user(self):
        left, right = socket.socketpair()
        try:
            self.assertEqual(server().peer_role(left), "operator")
            with self.assertRaisesRegex(ValueError, "peer_uid"):
                server(os.getuid() + 1).peer_role(right)
        finally:
            left.close()
            right.close()

    def test_server_refuses_foreign_pid_and_shell_without_effect(self):
        service = server()
        for op, args in (("kill", ["-TERM", str(os.getpid())]),
                         ("capture", ["/bin/sh", "-c", "id"])):
            left, right = socket.socketpair()
            service.slots.acquire()
            worker = threading.Thread(target=service.handle, args=(left,))
            worker.start()
            try:
                bridge.send(right, {"op": op, "argv": args})
                self.assertEqual(bridge.line(right)["ok"], False)
            finally:
                right.close()
                worker.join(timeout=2)
                self.assertFalse(worker.is_alive())

    def test_exact_interface_roster_refuses_other_real_interface_before_open(self):
        service = server()
        left, right = socket.socketpair()
        service.slots.acquire()
        with mock.patch.object(service, "peer_role", return_value="harness"), \
             mock.patch.object(bridge.os, "open", side_effect=AssertionError("unexpected_root_open")):
            worker = threading.Thread(target=service.handle, args=(left,))
            worker.start()
            try:
                bridge.send(right, {"op": "capture", "argv": capture("en7", "physical-en7.pcap")})
                self.assertEqual(bridge.line(right)["ok"], False)
            finally:
                right.close()
                worker.join(timeout=2)
                self.assertFalse(worker.is_alive())

    def test_same_uid_sibling_process_is_not_harness_descendant(self):
        harness = subprocess.Popen(["/bin/sleep", "5"])
        foreign = subprocess.Popen(["/bin/sleep", "5"])
        left, right = socket.socketpair()
        try:
            _, _, hsec, husec = bridge.process_identity(harness.pid)
            _, _, osec, ousec = bridge.process_identity(os.getpid())
            service = bridge.CaptureServer(OUT / "bridge.sock", OUT, os.getuid(), 300,
                                           harness.pid, (hsec, husec), os.getpid(),
                                           (osec, ousec), "en0", ["en0"], SOURCE,
                                           "0" * 64, "0" * 64)
            with mock.patch.object(bridge, "peer_pid", return_value=foreign.pid):
                with self.assertRaisesRegex(ValueError, "foreign_process_tree"):
                    service.peer_role(left)
        finally:
            left.close()
            right.close()
            harness.terminate()
            foreign.terminate()
            harness.wait(timeout=3)
            foreign.wait(timeout=3)

    def test_exact_harness_descendant_is_admitted_by_kernel_start_chain(self):
        harness = subprocess.Popen(["/usr/bin/python3", "-c",
            "import subprocess,time; p=subprocess.Popen(['/bin/sleep','5']); "
            "print(p.pid,flush=True); time.sleep(5)"], stdout=subprocess.PIPE, text=True)
        left, right = socket.socketpair()
        child_pid = None
        child_start = None
        try:
            child_pid = int(harness.stdout.readline().strip())
            child_start = bridge.process_identity(child_pid)[2:]
            _, _, hsec, husec = bridge.process_identity(harness.pid)
            _, _, osec, ousec = bridge.process_identity(os.getpid())
            service = bridge.CaptureServer(OUT / "bridge.sock", OUT, os.getuid(), 300,
                                           harness.pid, (hsec, husec), os.getpid(),
                                           (osec, ousec), "en0", ["en0"], SOURCE,
                                           "0" * 64, "0" * 64)
            with mock.patch.object(bridge, "peer_pid", return_value=child_pid):
                self.assertEqual(service.peer_role(left), "harness")
        finally:
            left.close()
            right.close()
            harness.terminate()
            harness.wait(timeout=3)
            harness.stdout.close()
            if child_pid is not None:
                try:
                    if bridge.process_identity(child_pid)[2:] == child_start:
                        os.kill(child_pid, signal.SIGTERM)
                except (ValueError, ProcessLookupError):
                    pass

    def test_user_owned_file_cannot_be_misreported_as_root_sealed_capture(self):
        with tempfile.TemporaryDirectory(prefix="aegis-b06-seal-") as td:
            name = Path(td) / "physical.pcap"
            fd = os.open(name, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
            os.write(fd, b"X" * 24)
            proc = subprocess.Popen(["/usr/bin/true"])
            proc.wait(timeout=3)
            st = os.fstat(fd)
            cap = bridge.Capture(str(name), proc, fd, st.st_dev, st.st_ino)
            service = server()
            service.out = Path(td)
            service.out_fd = os.open(td, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            directory = os.fstat(service.out_fd)
            service.out_identity = (directory.st_dev, directory.st_ino)
            try:
                with self.assertRaisesRegex(ValueError, "capture_inode_or_size"):
                    service.seal(cap)
                self.assertFalse(cap.sealed)
            finally:
                os.close(service.out_fd)
                os.close(fd)

    def test_held_output_refuses_parent_rebind_and_symlink(self):
        with tempfile.TemporaryDirectory(prefix="aegis-b06-out-fd-") as td:
            parent = Path(td)
            out = parent / "owned"
            out.mkdir(mode=0o700)
            foreign = parent / "foreign"
            foreign.mkdir(mode=0o700)
            service = server()
            service.out = out
            service.out_fd = os.open(out, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            held = os.fstat(service.out_fd)
            service.out_identity = (held.st_dev, held.st_ino)
            try:
                self.assertEqual(service.held_output(), service.out_fd)
                out.rename(parent / "moved")
                out.symlink_to(foreign, target_is_directory=True)
                with self.assertRaisesRegex(ValueError, "output_directory_rebound"):
                    service.held_output()
                self.assertFalse((foreign / "physical.pcap").exists())
            finally:
                os.close(service.out_fd)

    def test_final_leaf_symlink_and_hardlink_refuse_seal(self):
        with tempfile.TemporaryDirectory(prefix="aegis-b06-fd-leaf-") as td:
            out = Path(td)
            service = server()
            service.out = out
            service.out_fd = os.open(out, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            held = os.fstat(service.out_fd)
            service.out_identity = (held.st_dev, held.st_ino)
            name = out / "physical.pcap"
            foreign = out / "foreign"
            foreign.write_bytes(b"X" * 24)
            name.symlink_to(foreign)
            try:
                with self.assertRaises(OSError):
                    os.open(service.capture_leaf(str(name)),
                            os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                            0o600, dir_fd=service.held_output())
                name.unlink()
                fd = os.open("physical.pcap", os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600,
                             dir_fd=service.held_output())
                os.write(fd, b"X" * 24)
                os.link(name, out / "alias")
                proc = subprocess.Popen(["/usr/bin/true"])
                proc.wait(timeout=3)
                st = os.fstat(fd)
                with self.assertRaisesRegex(ValueError, "capture_inode_or_size"):
                    service.seal(bridge.Capture(str(name), proc, fd, st.st_dev, st.st_ino))
                os.close(fd)
            finally:
                os.close(service.out_fd)

    def test_bounded_command_caps_output_and_reaps_timeout(self):
        with self.assertRaisesRegex(ValueError, "command_output_bound"):
            bridge.bounded_command(["/usr/bin/python3", "-c", "print('X'*9000)"], 3, 1024)
        with self.assertRaisesRegex(ValueError, "command_output_bound"):
            bridge.bounded_command(["/usr/bin/python3", "-c",
                                    "import sys;sys.stderr.write('X'*9000)"],
                                   3, 1024, stderr_cap=1024)
        with self.assertRaises(TimeoutError):
            bridge.bounded_command(["/usr/bin/python3", "-c", "import time;time.sleep(10)"], 0.1, 1024)
        self.assertEqual(bridge.bounded_command(["/usr/bin/python3", "-c", "print('ok')"],
                                                3, 1024)[0], b"ok\n")
        payload = b"X" * (16 * 1024)
        argv = ["/usr/bin/python3", "-c",
                "import sys;print(len(sys.stdin.buffer.read()))"]
        self.assertEqual(bridge.bounded_command(argv, 3, 1024, input_bytes=payload,
                                                input_cap=128 * 1024)[0], b"16384\n")
        with self.assertRaisesRegex(ValueError, "command_input_bound"):
            bridge.bounded_command(argv, 3, 1024, input_bytes=payload, input_cap=8192)


if __name__ == "__main__":
    unittest.main()
