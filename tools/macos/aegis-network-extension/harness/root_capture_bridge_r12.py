#!/usr/bin/python3
"""Bounded S20 capture and exact R12 Wi-Fi privilege bridge; harness remains uid 501.

The root server accepts only the tcpdump/-l/owned-kill grammar used by
real-relay-window.sh.  It never executes a client supplied program or writes
through a client supplied path: output is an O_EXCL/O_NOFOLLOW fd below the
one admitted private run directory.  The launcher must copy this reviewed
file to a root-owned directory and verify its source SHA before execution.
"""

import argparse
import ctypes
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import select
import selectors
import shutil
import signal
import socket
import stat
import struct
import subprocess
import sys
import threading
import time
import tempfile

TCPDUMP = "/usr/sbin/tcpdump"
PERL = "/usr/bin/perl"
KILL = "/bin/kill"
ALARM_PL = "alarm shift; exec @ARGV; exit 127"
IFACE = re.compile(r"[A-Za-z][A-Za-z0-9]{0,20}\Z")
MAX_CAPTURES = 32
MAX_LINE = 4096
MAX_PCAP = 512 * 1024 * 1024
MAX_SNAPSHOT_OUTPUT = 128 * 1024
WIFI = "/usr/sbin/networksetup"
WIFI_RESTORE_CODE = r'''
import os, pathlib, signal, stat, subprocess, sys, time
signal.alarm(180)
root=pathlib.Path(sys.argv[1]); deadline=time.monotonic()+179
restore_at=deadline-30
ready=root/'wifi-restore.ready'; cancel=root/'wifi-restore.cancel'
terminal=root/'wifi-restore.terminal'
def finish(ok):
 fd=os.open(terminal,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'w') as f:
  f.write(('restored' if ok else 'failed')+'\n');f.flush();os.fsync(f.fileno())
 parent=os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
 try:os.fsync(parent)
 finally:os.close(parent)
 sys.exit(0 if ok else 3)
fd=os.open(ready,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
with os.fdopen(fd,'w') as f:
 f.write(str(os.getpid())+'\n');f.flush();os.fsync(f.fileno())
def power():
 try:
  left=deadline-time.monotonic()
  if left<=1:return False
  r=subprocess.run(['/usr/sbin/networksetup','-getairportpower','en0'],stdin=subprocess.DEVNULL,capture_output=True,timeout=min(5,left-1))
  return r.returncode==0 and r.stdout.strip().endswith(b': On')
 except (OSError,subprocess.SubprocessError):return False
while time.monotonic()<restore_at:
 try:
  st=cancel.lstat()
  if stat.S_ISREG(st.st_mode) and st.st_uid==0 and stat.S_IMODE(st.st_mode)==0o600 and power():finish(True)
 except FileNotFoundError:pass
 time.sleep(.25)
for attempt in range(30):
 left=deadline-time.monotonic()
 if left<=6:break
 try:subprocess.run(['/usr/sbin/networksetup','-setairportpower','en0','on'],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=min(10,left-6))
 except (OSError,subprocess.SubprocessError):pass
 if power():finish(True)
 time.sleep(min(.5,max(0,deadline-time.monotonic()-1)))
finish(False)
'''


def bounded_command(argv, timeout, cap, input_bytes=None, input_cap=None,
                    stderr_cap=0, env=None):
    """Collect a child with byte and clock bounds while it is still running."""
    if input_bytes is not None and len(input_bytes) > (cap if input_cap is None else input_cap):
        raise ValueError("command_input_bound")
    with tempfile.TemporaryFile() as input_file:
        if input_bytes is not None:
            input_file.write(input_bytes)
            input_file.seek(0)
        proc = subprocess.Popen(argv, stdin=input_file if input_bytes is not None else subprocess.DEVNULL,
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE if stderr_cap else subprocess.DEVNULL,
                                start_new_session=True, env=env)
        output = {"stdout": bytearray(), "stderr": bytearray()}
        deadline = time.monotonic() + timeout
        try:
            with selectors.DefaultSelector() as poller:
                poller.register(proc.stdout, selectors.EVENT_READ, ("stdout", cap))
                if stderr_cap:
                    poller.register(proc.stderr, selectors.EVENT_READ, ("stderr", stderr_cap))
                while poller.get_map():
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise TimeoutError("command_deadline")
                    for key, _ in poller.select(min(remaining, 0.2)):
                        name, limit = key.data
                        chunk = os.read(key.fileobj.fileno(), min(8192, limit - len(output[name]) + 1))
                        if not chunk:
                            poller.unregister(key.fileobj)
                            continue
                        output[name].extend(chunk)
                        if len(output[name]) > limit:
                            raise ValueError("command_output_bound")
            remaining = deadline - time.monotonic()
            if remaining <= 0 or proc.wait(timeout=remaining) != 0:
                raise ValueError("command_exit_or_deadline")
            return bytes(output["stdout"]), bytes(output["stderr"])
        finally:
            if proc.poll() is None:
                # This is a freshly spawned, still-live session leader.  Do
                # not signal a numeric process group after reaping the leader.
                try:
                    os.killpg(proc.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
                except PermissionError:
                    proc.terminate()
                try:
                    proc.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    try:
                        os.killpg(proc.pid, signal.SIGKILL)
                    except PermissionError:
                        proc.kill()
                    proc.wait(timeout=2)
            proc.stdout.close()
            if proc.stderr is not None:
                proc.stderr.close()


PROC_FIELDS = [(name, ctypes.c_uint32) for name in
               ("flags", "status", "xstatus", "pid", "ppid", "uid", "gid",
                "ruid", "rgid", "svuid", "svgid", "reserved")]
PROC_FIELDS += [("comm", ctypes.c_char * 16), ("name", ctypes.c_char * 32)]
PROC_FIELDS += [(name, ctypes.c_uint32) for name in
                ("nfiles", "pgid", "pjobc", "tdev", "tpgid")]
PROC_FIELDS += [("nice", ctypes.c_int32), ("start_sec", ctypes.c_uint64),
                ("start_usec", ctypes.c_uint64)]


class ProcBSDInfo(ctypes.Structure):
    # Darwin sys/proc_info.h struct proc_bsdinfo, size 136 on arm64. The
    # microsecond start stamp guards against PID reuse within one second.
    _fields_ = PROC_FIELDS


def process_identity(pid):
    info = ProcBSDInfo()
    libc = ctypes.CDLL("/usr/lib/libproc.dylib")
    libc.proc_pidinfo.argtypes = (ctypes.c_int, ctypes.c_int, ctypes.c_uint64,
                                 ctypes.c_void_p, ctypes.c_int)
    libc.proc_pidinfo.restype = ctypes.c_int
    got = libc.proc_pidinfo(pid, 3, 0, ctypes.byref(info), ctypes.sizeof(info))
    if got != ctypes.sizeof(info) or info.pid != pid or not info.start_sec:
        raise ValueError("process_identity_unavailable")
    return (info.ppid, info.uid, info.start_sec, info.start_usec)


def peer_pid(sock):
    return struct.unpack("i", sock.getsockopt(0, 2, 4))[0]  # SOL_LOCAL, LOCAL_PEERPID


@dataclass
class Capture:
    name: str
    proc: subprocess.Popen
    fd: int
    dev: int
    ino: int
    sealed: bool = False
    sha256: str = ""
    size: int = 0


def line(sock):
    data = bytearray()
    while len(data) <= MAX_LINE:
        b = sock.recv(1)
        if not b:
            break
        if b == b"\n":
            break
        data.extend(b)
    if len(data) > MAX_LINE:
        raise ValueError("request_too_long")
    return json.loads(data)


def send(sock, value):
    sock.sendall(json.dumps(value, sort_keys=True, separators=(",", ":")).encode() + b"\n")


def capture_argv(argv, out, now, deadline):
    """Return exact interface, held output name and two independent bounds."""
    if len(argv) >= 4 and argv[:3] == [PERL, "-e", ALARM_PL]:
        alarm = argv[3]
        argv = argv[4:]
    else:
        alarm = None
    if len(argv) != 15 or argv[0] != TCPDUMP or argv[1] != "-i":
        raise ValueError("capture_grammar")
    dev = argv[2]
    if not IFACE.fullmatch(dev):
        raise ValueError("interface")
    if argv[3:8] != ["-p", "-s", "160", "-B", "4096"]:
        raise ValueError("capture_flags")
    if argv[8] != "-G" or argv[10:14] != ["-W", "1", "-U", "-w"]:
        raise ValueError("capture_flags")
    bound = argv[9]
    if not bound.isascii() or not bound.isdecimal() or not 60 <= int(bound) <= 660:
        raise ValueError("capture_bound")
    if alarm is not None:
        if not alarm.isascii() or not alarm.isdecimal() or int(alarm) != int(bound) + 30:
            raise ValueError("capture_alarm")
    leaf = argv[14]
    # The source harness uses only the physical primary and named extra files.
    if not (leaf == str(out / "physical.pcap") or leaf == str(out / f"physical-{dev}.pcap")):
        raise ValueError("capture_path")
    if now >= deadline - 35:
        raise ValueError("server_deadline")
    return dev, leaf, min(now + int(alarm or bound) + 5, deadline)


def root_capture_command(dev, bound):
    # Preserve the original tcpdump grammar and give every interface an
    # independent alarm surviving an abrupt supervisor exit.
    return [PERL, "-e", ALARM_PL, str(int(bound) + 30), TCPDUMP, "-i", dev,
            "-p", "-s", "160", "-B", "4096", "-G", bound,
            "-W", "1", "-U", "-w", "-"]


def approved_snapshot(harness_source):
    # Interpret the *same reviewed AWK program* that the harness uses at
    # capture start and final all-interface review, from root-owned staged
    # bytes. A user-supplied interface roster alone is never authority.
    source = Path(harness_source).read_text()
    match = re.search(r"LEAK_IFACES_AWK='(.*?)'\nleak_ifaces\(\)", source, re.S)
    if not match or len(match.group(1)) > 8192:
        raise ValueError("reviewed_roster_predicate")
    raw, _ = bounded_command(["/sbin/ifconfig"], 5, MAX_SNAPSHOT_OUTPUT)
    names, _ = bounded_command(["/usr/bin/awk", "-v", "mode=names", match.group(1)],
                               5, 8192, input_bytes=raw, input_cap=MAX_SNAPSHOT_OUTPUT)
    route, _ = bounded_command(["/sbin/route", "-n", "get", "default"], 5, 8192)
    primary = next((line.split()[-1] for line in route.decode().splitlines()
                    if line.strip().startswith("interface:")), "")
    roster = set(names.decode().split()) | {primary}
    if (not primary or len(roster) > MAX_CAPTURES or
            any(not IFACE.fullmatch(x) for x in roster)):
        raise ValueError("physical_roster")
    return primary, roster


class CaptureServer:
    def __init__(self, socket_path, out, owner_uid, seconds, harness_pid,
                 harness_start, operator_pid, operator_start, primary, ifaces,
                 harness_source, harness_sha, bridge_sha, both_active=False):
        self.socket_path = Path(socket_path)
        self.out = Path(out)
        self.owner_uid = owner_uid
        self.deadline = time.monotonic() + seconds
        self.captures = {}
        self.guard = threading.Lock()
        self.used_names = set()
        self.close_requested = threading.Event()
        self.slots = threading.BoundedSemaphore(40)
        self.workers = []
        self.harness_pid = harness_pid
        self.harness_start = tuple(harness_start)
        self.operator_pid = operator_pid
        self.operator_start = tuple(operator_start)
        self.primary = primary
        self.ifaces = frozenset(ifaces)
        self.harness_source = Path(harness_source)
        self.harness_sha = harness_sha
        self.bridge_sha = bridge_sha
        self.both_active = both_active
        self.wifi_restore = None
        self.wifi_restored = False
        self.peer_receipt_sha = None
        self.out_fd = None
        self.out_identity = None
        if (not self.ifaces or len(self.ifaces) > MAX_CAPTURES or primary not in self.ifaces
                or any(not IFACE.fullmatch(x) for x in self.ifaces)):
            raise ValueError("approved_interface_roster")
        if both_active and (primary != 'en0' or 'en10' not in self.ifaces):
            raise ValueError('r12_both_active_roster')

    def wifi_power(self):
        raw, _ = bounded_command([WIFI, '-getairportpower', 'en0'], 20, 1024)
        if not raw.strip().endswith((b': On', b': Off')):
            raise ValueError('wifi_power_unreadable')
        return raw.strip().rsplit(b': ', 1)[-1].decode('ascii')

    def peer_receipt_fresh(self, expected):
        if not re.fullmatch(r'[0-9a-f]{64}', expected):
            raise ValueError('r12_peer_receipt_pin')
        fd = os.open('physical-switch-peers.json',
                     os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                     dir_fd=self.held_output())
        try:
            first = os.fstat(fd)
            if (not stat.S_ISREG(first.st_mode) or first.st_uid != self.owner_uid or
                    first.st_nlink != 1 or stat.S_IMODE(first.st_mode) != 0o600 or
                    not 0 < first.st_size <= 65536):
                raise ValueError('r12_peer_receipt_custody')
            raw = os.read(fd, first.st_size + 1)
            after = os.fstat(fd)
            named = os.stat('physical-switch-peers.json', dir_fd=self.held_output(),
                            follow_symlinks=False)
            fields = ('st_dev','st_ino','st_uid','st_mode','st_nlink','st_size',
                      'st_mtime_ns','st_ctime_ns')
            if (len(raw) != first.st_size or
                    any(getattr(first,k) != getattr(after,k) or
                        getattr(first,k) != getattr(named,k) for k in fields) or
                    hashlib.sha256(raw).hexdigest() != expected):
                raise ValueError('r12_peer_receipt_changed')
            value = json.loads(raw)
            checked = value.get('checked_unix')
            if type(checked) is not int:
                raise ValueError('r12_peer_measurement_stale_or_changed')
            age = int(time.time()) - checked
            if (value.get('schema') != 'aegis_macos_r12_scoped_physical_peers_v1' or
                    value.get('identity_request_sent') is not False or
                    not 0 <= age <= 60 or
                    [r.get('interface') for r in value.get('interfaces', [])] !=
                    ['en0','en10'] or
                    not 1 <= len(value.get('exact_public_peer_set', [])) <= 2):
                raise ValueError('r12_peer_measurement_stale_or_changed')
        finally:
            os.close(fd)

    def wifi_action(self, action):
        if not self.both_active or self.primary != 'en0' or 'en10' not in self.ifaces:
            raise ValueError('wifi_action_not_admitted')
        if not self.identity_alive(self.harness_pid, self.harness_start):
            raise ValueError('wifi_harness_identity')
        with self.guard:
            if action == 'arm':
                if self.peer_receipt_sha is None:
                    raise ValueError('r12_peer_receipt_unbound')
                self.peer_receipt_fresh(self.peer_receipt_sha)
                if self.wifi_restore is not None or self.wifi_power() != 'On':
                    raise ValueError('wifi_restore_not_fresh')
                expected = {str(self.out / ('physical.pcap' if dev == self.primary
                                            else 'physical-' + dev + '.pcap'))
                            for dev in self.ifaces}
                if ({c.name for c in self.captures.values()} != expected or
                        any(c.sealed or c.proc.poll() is not None
                            for c in self.captures.values())):
                    raise ValueError('wifi_physical_capture_not_armed')
                root = self.socket_path.parent
                self.wifi_restore = subprocess.Popen(
                    ['/usr/bin/python3', '-I', '-c', WIFI_RESTORE_CODE, str(root)],
                    stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL, start_new_session=True)
                ready = root / 'wifi-restore.ready'
                until = time.monotonic() + 3
                while time.monotonic() < until and not ready.exists():
                    if self.wifi_restore.poll() is not None:
                        raise ValueError('wifi_restore_exited_before_arm')
                    time.sleep(.05)
                fd = os.open(ready, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
                try:
                    st = os.fstat(fd)
                    raw = os.read(fd, 32)
                    if (not stat.S_ISREG(st.st_mode) or st.st_uid != 0 or st.st_nlink != 1
                            or stat.S_IMODE(st.st_mode) != 0o600
                            or raw != (str(self.wifi_restore.pid)+'\n').encode()
                            or self.wifi_restore.poll() is not None):
                        raise ValueError('wifi_restore_not_armed')
                finally:
                    os.close(fd)
                return
            if self.wifi_restore is None:
                raise ValueError('wifi_restore_missing')
            if action == 'off':
                if self.wifi_restore.poll() is not None:
                    raise ValueError('wifi_restore_not_live')
                bounded_command([WIFI, '-setairportpower', 'en0', 'off'], 20, 1024)
                if self.wifi_power() != 'Off':
                    raise ValueError('wifi_off_unconfirmed')
                return
            if action == 'on':
                bounded_command([WIFI, '-setairportpower', 'en0', 'on'], 20, 1024)
                if self.wifi_power() != 'On':
                    raise ValueError('wifi_on_unconfirmed')
                fd = os.open(self.socket_path.parent / 'wifi-restore.cancel',
                             os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                try:
                    os.write(fd, b'restored\n'); os.fsync(fd)
                finally:
                    os.close(fd)
                if self.wifi_restore.wait(timeout=5) != 0:
                    raise ValueError('wifi_restore_actor_failed')
                terminal = self.socket_path.parent / 'wifi-restore.terminal'
                fd = os.open(terminal, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
                try:
                    st = os.fstat(fd)
                    if (not stat.S_ISREG(st.st_mode) or st.st_uid != 0 or st.st_nlink != 1
                            or stat.S_IMODE(st.st_mode) != 0o600 or
                            os.read(fd, 32) != b'restored\n'):
                        raise ValueError('wifi_restore_terminal_changed')
                finally:
                    os.close(fd)
                self.wifi_restored = True
                return
            raise ValueError('wifi_action_unknown')

    def identity_alive(self, pid, start):
        try:
            _, uid, sec, usec = process_identity(pid)
        except ValueError:
            return False
        return uid == self.owner_uid and (sec, usec) == start

    def validate(self):
        if os.geteuid() != 0:
            raise ValueError("root_required")
        parent = self.socket_path.parent
        st = parent.lstat()
        if (parent.parent != Path("/private/tmp") or not parent.name.startswith("aegis-b06-capture-")
                or self.socket_path.name != "bridge.sock" or not stat.S_ISDIR(st.st_mode)
                or st.st_uid != 0 or stat.S_IMODE(st.st_mode) != 0o711):
            raise ValueError("socket_parent")
        st = self.out.lstat()
        if (self.out.parent != Path("/private/tmp") or not self.out.name.startswith("aegis-b06-s20-")
                or self.out.resolve() != self.out or not stat.S_ISDIR(st.st_mode)
                or st.st_uid != self.owner_uid or stat.S_IMODE(st.st_mode) != 0o700):
            raise ValueError("output_custody")
        if self.socket_path.exists() or self.socket_path.is_symlink():
            raise ValueError("socket_exists")
        if not self.identity_alive(self.harness_pid, self.harness_start):
            raise ValueError("harness_identity")
        if not self.identity_alive(self.operator_pid, self.operator_start):
            raise ValueError("operator_identity")
        for path, expected in ((self.harness_source, self.harness_sha),
                               (Path(__file__), self.bridge_sha)):
            info = path.lstat()
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or
                    info.st_mode & 0o022 or hashlib.sha256(path.read_bytes()).hexdigest() != expected):
                raise ValueError("root_staged_source")
            ancestor = path.parent
            while ancestor != parent:
                held = ancestor.lstat()
                if (not stat.S_ISDIR(held.st_mode) or held.st_uid != 0 or
                        held.st_mode & 0o022 or parent not in ancestor.parents):
                    raise ValueError("root_staged_ancestor")
                ancestor = ancestor.parent
        primary, roster = approved_snapshot(self.harness_source)
        if primary != self.primary or roster != self.ifaces:
            raise ValueError("approved_roster_changed")
        free = os.statvfs("/System/Volumes/Data")
        if free.f_bavail * free.f_frsize < (35 * 1024**3 + len(roster) * MAX_PCAP + 1024**3):
            raise ValueError("capture_disk_reserve")
        # The owner may rename the output pathname after this check.  Every
        # privileged leaf operation below uses this held directory instead.
        fd = os.open(self.out, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        held = os.fstat(fd)
        path = self.out.lstat()
        if ((held.st_dev, held.st_ino) != (st.st_dev, st.st_ino)
                or (path.st_dev, path.st_ino) != (held.st_dev, held.st_ino)
                or not stat.S_ISDIR(held.st_mode) or held.st_uid != self.owner_uid
                or stat.S_IMODE(held.st_mode) != 0o700):
            os.close(fd)
            raise ValueError("output_directory_rebound")
        self.out_fd = fd
        self.out_identity = (held.st_dev, held.st_ino)

    def held_output(self):
        if self.out_fd is None:
            raise ValueError("output_directory_unheld")
        held = os.fstat(self.out_fd)
        path = self.out.lstat()
        if ((held.st_dev, held.st_ino) != self.out_identity
                or (path.st_dev, path.st_ino) != self.out_identity
                or not stat.S_ISDIR(held.st_mode) or held.st_uid != self.owner_uid
                or stat.S_IMODE(held.st_mode) != 0o700):
            raise ValueError("output_directory_rebound")
        return self.out_fd

    def capture_leaf(self, name):
        leaf = Path(name).name
        if name != str(self.out / leaf) or not (leaf == "physical.pcap" or
                IFACE.fullmatch(leaf.removeprefix("physical-").removesuffix(".pcap")) and
                leaf.startswith("physical-") and leaf.endswith(".pcap")):
            raise ValueError("capture_leaf")
        return leaf

    def peer_role(self, sock):
        uid = ctypes.c_uint()
        gid = ctypes.c_uint()
        if ctypes.CDLL(None).getpeereid(sock.fileno(), ctypes.byref(uid), ctypes.byref(gid)) != 0:
            raise ValueError("peer_credential_unavailable")
        if uid.value != self.owner_uid:
            raise ValueError("peer_uid")
        pid = peer_pid(sock)
        if pid == self.operator_pid and self.identity_alive(pid, self.operator_start):
            return "operator"
        seen = set()
        for _ in range(16):
            if pid <= 1 or pid in seen:
                break
            seen.add(pid)
            ppid, p_uid, sec, usec = process_identity(pid)
            if p_uid != self.owner_uid:
                break
            if pid == self.harness_pid:
                if (sec, usec) == self.harness_start:
                    return "harness"
                break
            pid = ppid
        raise ValueError("foreign_process_tree")

    def seal(self, capture):
        if capture.proc.poll() is None:
            raise ValueError("capture_still_running")
        held = os.fstat(capture.fd)
        path = os.stat(self.capture_leaf(capture.name), dir_fd=self.held_output(), follow_symlinks=False)
        if (not stat.S_ISREG(held.st_mode) or held.st_nlink != 1 or held.st_uid != 0
                or (held.st_dev, held.st_ino) != (capture.dev, capture.ino)
                or (path.st_dev, path.st_ino) != (capture.dev, capture.ino)
                or held.st_size < 24 or held.st_size > MAX_PCAP):
            raise ValueError("capture_inode_or_size")
        os.fsync(capture.fd)
        h = hashlib.sha256()
        offset = 0
        while offset < held.st_size:
            part = os.pread(capture.fd, min(1024 * 1024, held.st_size - offset), offset)
            if not part:
                raise ValueError("capture_short_read")
            h.update(part)
            offset += len(part)
        capture.sha256 = h.hexdigest()
        capture.size = held.st_size
        os.fchmod(capture.fd, 0o400)
        os.fchown(capture.fd, self.owner_uid, -1)
        os.fsync(capture.fd)
        after = os.stat(self.capture_leaf(capture.name), dir_fd=self.held_output(), follow_symlinks=False)
        if ((after.st_dev, after.st_ino, after.st_size, after.st_uid,
             stat.S_IMODE(after.st_mode)) !=
                (capture.dev, capture.ino, capture.size, self.owner_uid, 0o400)):
            raise ValueError("capture_handoff_identity")
        capture.sealed = True

    def seal_stable(self, capture):
        if not capture.sealed or capture.proc.poll() is None:
            return False
        try:
            now = os.stat(self.capture_leaf(capture.name), dir_fd=self.held_output(), follow_symlinks=False)
            held = os.fstat(capture.fd)
            if ((now.st_dev, now.st_ino, now.st_size) !=
                    (capture.dev, capture.ino, capture.size)
                    or (held.st_dev, held.st_ino) != (capture.dev, capture.ino)
                    or now.st_nlink != 1 or now.st_uid != self.owner_uid
                    or stat.S_IMODE(now.st_mode) != 0o400):
                return False
            h = hashlib.sha256()
            offset = 0
            while offset < capture.size:
                part = os.pread(capture.fd, min(1024 * 1024, capture.size - offset), offset)
                if not part:
                    return False
                h.update(part)
                offset += len(part)
            return h.hexdigest() == capture.sha256
        except OSError:
            return False

    def handle(self, sock):
        proc = None
        try:
            sock.settimeout(5)
            role = self.peer_role(sock)
            req = line(sock)
            if type(req) is not dict or set(req) != {"op", "argv"} or type(req["argv"]) is not list:
                raise ValueError("request_schema")
            op, argv = req["op"], req["argv"]
            if not all(type(v) is str and len(v) < 1024 for v in argv):
                raise ValueError("argv_schema")
            if time.monotonic() >= self.deadline:
                raise ValueError("server_expired")
            if op == "ready" and role == "operator" and not argv:
                send(sock, {"ok": True})
                return
            if op == 'peer-bind' and role == 'operator' and len(argv) == 1 and self.both_active:
                with self.guard:
                    if self.peer_receipt_sha is not None:
                        raise ValueError('r12_peer_receipt_already_bound')
                    self.peer_receipt_fresh(argv[0])
                    self.peer_receipt_sha = argv[0]
                send(sock, {'ok': True})
                return
            if op == 'wifi' and role == 'harness' and len(argv) == 1:
                self.wifi_action(argv[0])
                send(sock, {'ok': True})
                return
            if op == "close" and role != "operator":
                raise ValueError("close_role")
            if op not in ("ready", "close") and role != "harness":
                raise ValueError("harness_role")
            if op == "check" and argv in ([TCPDUMP], [PERL], [KILL]):
                send(sock, {"ok": True})
                return
            if op == "close" and not argv:
                if self.wifi_restore is not None and (not self.wifi_restored or
                        self.wifi_restore.poll() is None or self.wifi_power() != 'On'):
                    raise ValueError('wifi_restore_not_terminal')
                with self.guard:
                    if any(not self.seal_stable(c) for c in self.captures.values()):
                        raise ValueError("capture_not_sealed_or_changed")
                self.close_requested.set()
                send(sock, {"ok": True})
                return
            if op == "leaf" and len(argv) == 1:
                with self.guard:
                    pair = next(((pid, cap) for pid, cap in self.captures.items()
                                 if cap.name == argv[0] and not cap.sealed), None)
                send(sock, {"ok": bool(pair), "pid": pair[0] if pair else 0})
                return
            if op == "seal" and len(argv) == 1:
                with self.guard:
                    cap = next((c for c in self.captures.values() if c.name == argv[0]), None)
                    if cap is None or not self.seal_stable(cap):
                        raise ValueError("capture_unsealed")
                    send(sock, {"ok": True, "sha256": cap.sha256, "size": cap.size})
                return
            if op == "kill" and len(argv) == 2 and argv[0] in ("-INT", "-TERM") and argv[1].isdecimal():
                pid = int(argv[1])
                with self.guard:
                    owned = self.captures.get(pid)
                    if owned is None or owned.proc.poll() is not None:
                        raise ValueError("not_owned_capture")
                    owned.proc.send_signal(signal.SIGINT if argv[0] == "-INT" else signal.SIGTERM)
                send(sock, {"ok": True})
                return
            if op != "capture":
                raise ValueError("operation")
            now = time.monotonic()
            dev, filename, end = capture_argv(argv, self.out, now, self.deadline)
            if dev not in self.ifaces or ((filename == str(self.out / "physical.pcap")) != (dev == self.primary)):
                raise ValueError("unapproved_interface")
            capture_bound = argv[9 if argv[0] == TCPDUMP else 13]
            with self.guard:
                if filename in self.used_names or len(self.used_names) >= MAX_CAPTURES:
                    raise ValueError("capture_reuse_or_limit")
                self.used_names.add(filename)
                fd = os.open(self.capture_leaf(filename),
                             os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                             0o600, dir_fd=self.held_output())
                try:
                    # A root opened descriptor prevents a user-controlled path
                    # replacement from redirecting privileged tcpdump writes.
                    # The Perl alarm survives exec. Even if this supervisor
                    # is killed, a quiet interface cannot capture forever.
                    proc = subprocess.Popen(root_capture_command(dev, capture_bound),
                                            stdin=subprocess.DEVNULL, stdout=fd, stderr=subprocess.PIPE,
                                            close_fds=True, start_new_session=True)
                except BaseException:
                    os.close(fd)
                    raise
                st = os.fstat(fd)
                self.captures[proc.pid] = Capture(filename, proc, fd, st.st_dev, st.st_ino)
            send(sock, {"ok": True, "pid": proc.pid})
            # Keep the unprivileged sudo shim alive as long as its capture.
            # Only bounded tcpdump diagnostic output crosses the socket.
            stderr_left = 8192
            next_space = 0
            while proc.poll() is None and time.monotonic() < end:
                if os.fstat(self.captures[proc.pid].fd).st_size > MAX_PCAP:
                    proc.kill()
                    proc.wait(timeout=3)
                    raise ValueError("capture_size_limit")
                if time.monotonic() >= next_space:
                    free = os.statvfs("/System/Volumes/Data")
                    if free.f_bavail * free.f_frsize < 35 * 1024**3:
                        proc.kill()
                        proc.wait(timeout=3)
                        raise ValueError("capture_disk_floor")
                    next_space = time.monotonic() + 1
                ready, _, _ = select.select([proc.stderr], [], [], min(0.2, max(0, end - time.monotonic())))
                chunk = os.read(proc.stderr.fileno(), 1024) if ready else b""
                if chunk and stderr_left:
                    send(sock, {"stderr": chunk[:stderr_left].decode("utf-8", "replace")})
                    stderr_left = max(0, stderr_left - len(chunk))
                else:
                    time.sleep(0.1)
            if proc.poll() is None:
                proc.send_signal(signal.SIGINT)
                try:
                    proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=3)
            with self.guard:
                self.seal(self.captures[proc.pid])
            send(sock, {"exit": proc.returncode})
        except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError) as error:
            try:
                send(sock, {"ok": False, "reason": type(error).__name__})
            except OSError:
                pass
        finally:
            # A dead harness or sudo shim must not leave a root capture
            # running. The whole server also has an independent outer bound.
            if proc is not None and proc.poll() is None:
                proc.send_signal(signal.SIGINT)
                try:
                    proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=3)
            if proc is not None:
                with self.guard:
                    cap = self.captures.get(proc.pid)
                    if cap is not None and not cap.sealed:
                        try:
                            self.seal(cap)
                        except (OSError, ValueError):
                            pass
            sock.close()
            self.slots.release()

    def serve(self):
        self.validate()
        server = socket.socket(socket.AF_UNIX)
        try:
            server.bind(str(self.socket_path))
            os.chown(self.socket_path, self.owner_uid, -1)
            os.chmod(self.socket_path, 0o600)
            server.listen(40)
            server.settimeout(0.5)
            while time.monotonic() < self.deadline and not self.close_requested.is_set():
                if not self.identity_alive(self.harness_pid, self.harness_start):
                    break
                try:
                    peer, _ = server.accept()
                except socket.timeout:
                    continue
                if not self.slots.acquire(blocking=False):
                    peer.close()
                    continue
                worker = threading.Thread(target=self.handle, args=(peer,), daemon=True)
                self.workers.append(worker)
                worker.start()
        finally:
            if self.wifi_restore is not None:
                try:
                    self.wifi_restored = (self.wifi_restore.wait(timeout=210) == 0
                                          and self.wifi_power() == 'On' and
                                          (self.socket_path.parent / 'wifi-restore.terminal').read_bytes()
                                          == b'restored\n')
                except (subprocess.TimeoutExpired, OSError, ValueError):
                    self.wifi_restored = False
            with self.guard:
                all_owned = list(self.captures.values())
            for cap in all_owned:
                proc = cap.proc
                if proc.poll() is None:
                    proc.send_signal(signal.SIGINT)
            stop_by = time.monotonic() + 3
            for cap in all_owned:
                proc = cap.proc
                try:
                    proc.wait(timeout=max(0, stop_by - time.monotonic()))
                except subprocess.TimeoutExpired:
                    pass
            for cap in all_owned:
                proc = cap.proc
                if proc.poll() is None:
                    proc.kill()
            kill_by = time.monotonic() + 3
            for cap in all_owned:
                proc = cap.proc
                try:
                    proc.wait(timeout=max(0, kill_by - time.monotonic()))
                except subprocess.TimeoutExpired:
                    pass
            worker_by = time.monotonic() + 5
            for worker in self.workers:
                worker.join(timeout=max(0, worker_by - time.monotonic()))
            for cap in all_owned:
                try:
                    if not cap.sealed:
                        self.seal(cap)
                except (OSError, ValueError):
                    pass
                os.close(cap.fd)
            server.close()
            self.socket_path.unlink(missing_ok=True)
            if self.out_fd is not None:
                os.close(self.out_fd)
                self.out_fd = None

    def cleanup_root_staging(self):
        if self.wifi_restore is not None and not self.wifi_restored:
            return  # retain the exact source/actor proof on uncertain restoration
        parent = self.socket_path.parent
        try:
            st = parent.lstat()
            if (parent.parent != Path("/private/tmp") or not parent.name.startswith("aegis-b06-capture-")
                    or not stat.S_ISDIR(st.st_mode) or st.st_uid != 0):
                return
            source = parent / "source"
            src_st = source.lstat()
            if not stat.S_ISDIR(src_st.st_mode) or src_st.st_uid != 0:
                return
            if self.wifi_restore is not None:
                for leaf in ('wifi-restore.ready', 'wifi-restore.cancel',
                             'wifi-restore.terminal'):
                    named = parent / leaf
                    if not named.exists() and not named.is_symlink():
                        continue
                    st = named.lstat()
                    if (not stat.S_ISREG(st.st_mode) or st.st_uid != 0 or
                            st.st_nlink != 1 or stat.S_IMODE(st.st_mode) != 0o600):
                        return
                    named.unlink()
            shutil.rmtree(source)
            (parent / "source.tar").unlink(missing_ok=True)
            self.socket_path.unlink(missing_ok=True)
            parent.rmdir()
        except OSError:
            # A failed cleanup leaves only source bytes, no root actor. The
            # operator records bridge closure refusal if the socket remains.
            pass


def client(argv, socket_path):
    if argv[:2] == ["-n", "-l"] and len(argv) == 3:
        op, args = "check", argv[2:]
    elif argv[:3] == ["-n", KILL, "-INT"] or argv[:3] == ["-n", KILL, "-TERM"]:
        op, args = "kill", argv[2:]
    elif argv[:1] == ["--leaf"]:
        op, args = "leaf", argv[1:]
    elif argv[:1] == ["--seal"]:
        op, args = "seal", argv[1:]
    elif argv == ["--close"]:
        op, args = "close", []
    elif argv == ["--ready"]:
        op, args = "ready", []
    elif len(argv) == 2 and argv[0] == '--wifi' and argv[1] in ('arm','off','on'):
        op, args = 'wifi', argv[1:]
    elif argv[:1] == ["-n"]:
        op, args = "capture", argv[1:]
    else:
        return 3
    sock = socket.socket(socket.AF_UNIX)
    sock.settimeout(5)
    try:
        sock.connect(socket_path)
        send(sock, {"op": op, "argv": args})
        first = line(sock)
    except (OSError, ValueError, json.JSONDecodeError):
        return 3
    if not first.get("ok"):
        return 3
    if op == "leaf":
        if not first["pid"]:
            return 3
        print(first["pid"])
        return 0
    if op == "seal":
        print(first["sha256"])
        return 0
    if op != "capture":
        return 0
    try:
        bound = int(args[args.index("-G") + 1])
    except (IndexError, ValueError):
        return 3
    if not 60 <= bound <= 660:
        return 3
    final = time.monotonic() + bound + 35
    sock.settimeout(3)
    while True:
        if time.monotonic() >= final:
            return 3
        try:
            item = line(sock)
        except socket.timeout:
            continue
        except (OSError, ValueError, json.JSONDecodeError):
            return 3
        if "stderr" in item:
            sys.stderr.write(item["stderr"])
        elif "exit" in item:
            return 0 if item["exit"] == 0 else 1


def main():
    if len(sys.argv) >= 2 and sys.argv[1] == "client":
        socket_path = os.environ.get("AEGIS_CAPTURE_SOCKET", "")
        if not socket_path.startswith("/private/tmp/aegis-b06-capture-"):
            raise ValueError("socket_path")
        return client(sys.argv[2:], socket_path)
    p = argparse.ArgumentParser()
    p.add_argument("role", choices=("serve",))
    p.add_argument("--socket", required=True)
    p.add_argument("--out", required=True)
    p.add_argument("--uid", type=int, required=True)
    p.add_argument("--seconds", type=int, required=True)
    p.add_argument("--harness-pid", type=int, required=True)
    p.add_argument("--harness-start", required=True)
    p.add_argument("--operator-pid", type=int, required=True)
    p.add_argument("--operator-start", required=True)
    p.add_argument("--primary", required=True)
    p.add_argument("--ifaces", required=True)
    p.add_argument("--harness-source", required=True)
    p.add_argument("--harness-sha256", required=True)
    p.add_argument("--bridge-sha256", required=True)
    p.add_argument('--both-active', action='store_true')
    a = p.parse_args()
    if not 60 <= a.seconds <= 720 or a.uid <= 0 or a.harness_pid <= 1 or a.operator_pid <= 1:
        raise ValueError("server_bounds")
    def start(value):
        if not re.fullmatch(r"[1-9][0-9]{0,11}:[0-9]{1,6}", value):
            raise ValueError("start_identity")
        sec, usec = map(int, value.split(":"))
        if usec >= 1_000_000:
            raise ValueError("start_identity")
        return sec, usec
    server = CaptureServer(a.socket, a.out, a.uid, a.seconds, a.harness_pid,
                           start(a.harness_start), a.operator_pid, start(a.operator_start),
                           a.primary, a.ifaces.split(","), a.harness_source,
                           a.harness_sha256, a.bridge_sha256, a.both_active)
    try:
        server.serve()
    finally:
        server.cleanup_root_staging()
    return 0


if __name__ == "__main__":
    sys.exit(main())
