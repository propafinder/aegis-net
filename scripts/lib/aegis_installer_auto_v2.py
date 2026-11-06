#!/usr/bin/env python3
"""Administrator coordinator for the protected AUTO V2 installation transaction.

The Rust worker owns the install lock and every publication.  This module only
passes the fixed protocol, installs the already admitted candidate executable,
and keeps a durable pointer to any interrupted stage for explicit recovery.
"""

import argparse
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import select
import stat
import subprocess
import sys
import time
import re
import pwd
import grp
import tomllib
import ctypes
import secrets
import threading
import types

# Python -I excludes the script directory from sys.path. Older retained
# releases legitimately lack this newly added helper, so load it only when a
# persistent uninstall namespace is present or a typed uninstall verb runs.
class _UninstallJournalSource:
    def __init__(self):
        self.module = None

    def __getattr__(self, name):
        if self.module is None:
            source = Path(__file__).with_name("aegis_auto_uninstall_journal.py")
            spec = importlib.util.spec_from_file_location(
                "aegis_auto_uninstall_journal", source)
            if spec is None or spec.loader is None:
                raise RuntimeError("AUTO uninstall journal source unavailable")
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            self.module = module
        return getattr(self.module, name)


uninstall_journal = _UninstallJournalSource()


PROTOCOL = "auto-config-snapshot-v2"
INSTALLED_GUARDIAN = Path('/usr/local/lib/aegis/helpers/lib/aegis_auto_guardian.py')
_GUARDIAN_CACHE = None
_GUARDIAN_CACHE_LOCK = threading.RLock()
CONTROL = Path("/var/lib/aegis-auto/control")
POINTER = "current.json"
PREPARE_CURRENT = "prepare-current.json"
PREPARE_COMPLETED = "prepare-completed.json"
PREPARE_STAGE_CREATED = "prepare-stage-created.json"
PREPARE_HANDOFF = CONTROL / PREPARE_CURRENT
PASSIVE_INTENT = "fresh-passive-intent.json"
PASSIVE_INPUT = "fresh-passive-input"
PASSIVE_READY = "fresh-passive-ready.json"
FIRST_ARM_INTENT = "fresh-first-arm-intent.json"
PASSIVE_SUCCESSOR_INTENT = "passive-successor-retirement-intent.json"
PASSIVE_SUCCESSOR_RETIRED = "passive-successor-retired.json"
PASSIVE_ABORT_PENDING = Path("/var/lib/aegis-auto/fresh-passive-abort-current.json")
PASSIVE_ABORT_ARCHIVES = Path("/var/lib/aegis-auto/fresh-passive-aborts")
PASSIVE_ABORT_WITNESS_SOCKET = Path("/run/aegis-auto-topology/authority.sock")
PASSIVE_ABORT_RETIRED_STAGES = Path("/run/aegis-auto-retired-stages")
PASSIVE_ABORT_STAGE_PARENT = Path("/run/aegis-installer-config-snapshots")
PASSIVE_ABORT_STAGE_MAX = 128 << 20
PASSIVE_ABORT_STAGE_ENTRIES = 1024
PASSIVE_ABORT_COPY_SECONDS = 60
PASSIVE_LEAVES = ("aegis-client.toml", "ca.pem",
                  "aegis-client-privileged-dns.toml", "masque-ca.pem")
PASSIVE_FILE_MAX = 16 << 20  # Rust CaptureLimits::default().file_bytes
PASSIVE_OPTIONS = ("masque_server", "masque_ca", "wide_interface",
                   "source_manifest_url", "source_release_channel", "requested_mode")
MAX_REPLY = 8192
PHASE_TIMEOUT = 30.0
BEGIN_CAPTURE_TIMEOUT = 45.0
WORKER_TIMEOUT = 900.0
REASONS = frozenset({
    "phase_refused", "native_recovery_required", "activation_owner_unavailable",
    "projection_semantics_changed", "native_capture_guard_not_ready",
    "coordinator_disconnected",
})
RELOAD_FAILURES = frozenset({
    'reload_worker_before', 'reload_worker_after', 'reload_dispatch', 'reload_stage',
    'reload_committed_policy', 'reload_recorded_namespace', 'reload_intent',
    'reload_native_unknown', 'reload_receipt_validation', 'reload_receipt_write',
    'reload_namespace_commit', 'reload_native_preflight',
    'reload_native_preparation', 'reload_native_revalidate',
    'reload_native_fixed_command', 'reload_native_fixed_executable',
    'reload_native_fixed_spawn', 'reload_native_fixed_pipes',
    'reload_native_fixed_wait', 'reload_native_fixed_drain',
    'reload_native_fixed_stderr', 'reload_native_fixed_cleanup',
    'reload_native_fixed_exit', 'reload_native_fixed_readback',
    'reload_native_fixed_stdout', 'reload_native_acceptance',
    'reload_native_receipt',
} | {f'reload_{pass_name}_{gate}'
     for pass_name in ('first', 'second', 'final')
     for gate in ('precheck', 'authority', 'pid1_first', 'cgroup',
                  'pid1_second', 'postcheck', 'cgroup_revalidate', 'pid1_final')})
FAILURE_PHASES = frozenset({
    "preflight", "boot_successor", "prepare", "prepare_handoff", "reference_custody", "stage_pointer",
    "prepare_handoff_archive", "worker_ready", "inspect",
    "guardian_mode", "before_custody", "account", "bind_runtime",
    "publish_binary", "commit_custody", "commit_state", "commit_config",
    "seal_receipt", "publish_policy", "reload_policy", "published_verify",
    "publish_metadata", "activation_verify", "begin_capture", "finalize",
    "terminal_readback", "generation_seal", "package_preflight", "package_stop",
    "package_successor", "package_lock", "package_prepare_guard", "package_block_guard",
    "package_retire_guard", "package_verify_retired", "package_unpack",
    "package_admit_guard", "package_resume", "package_install",
    "package_retire_passive", "package_verify_passive",
    "package_retry_status", "package_configure", "package_actor_progress",
    "package_terminal_readback", "package_compensated", "package_advance",
})



_PHASE = "entry"
_PHASE_NAMES = frozenset({
    "entry", "abort_pending", "boot_successor", "lock", "signed_package", "dpkg_status", "dpkg_verify",
    "absent_path", "empty_dir", "snapshots", "control", "installed_file", "env",
    "unit_template", "unit_state", "private_units", "jobs", "lock_final",
    "identity", "locate_lock", "locate_abort_pending", "locate_control",
    "locate_intent", "locate_empty", "locate_shape", "locate_boot",
})


def _set_phase(name, index=None):
    global _PHASE
    if name not in _PHASE_NAMES or (index is not None and
            (type(index) is not int or not 0 <= index <= 4096)):
        raise Refused()
    _PHASE = name if index is None else f"{name}:{index}"


def _failure_line(error):
    line = 0
    trace = error.__traceback__
    while trace is not None:
        if (trace.tb_frame.f_code.co_filename == __file__ and
                trace.tb_frame.f_code.co_name not in ("need", "call_output")):
            line = trace.tb_lineno
        trace = trace.tb_next
    return line if 0 <= line <= 10000 else 0


def _failure_class(error):
    return ("fresh_passive_aborted_reapply_required" if isinstance(
                error, FreshPassiveAbortedReapplyRequired) else
            "refused" if isinstance(error, Refused) else
            "timeout" if isinstance(error, (TimeoutError, subprocess.TimeoutExpired)) else
            "os_error" if isinstance(error, OSError) else "unexpected")


class Refused(Exception):
    pass


class FreshPassiveAbortedReapplyRequired(Refused):
    """A completed abort archived package-owned files while dpkg stayed installed."""


def need(ok, reason=None):
    if not ok:
        if reason is None:
            raise Refused()
        raise Refused(reason)


def absolute(raw):
    path = Path(raw)
    need(path.is_absolute() and str(path) != "/" and
         all(part not in (".", "..") for part in raw.split("/")) and
         "//" not in raw and not any(ord(ch) < 32 for ch in raw))
    return path


def held_root_file(path, maximum, modes=None):
    """Open a bounded root-owned regular file through nofollow directories."""
    path = absolute(str(path))
    parent = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for part in path.parts[1:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW |
                            os.O_CLOEXEC, dir_fd=parent)
            info = os.fstat(child)
            try:
                need(stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == 0 and
                     not stat.S_IMODE(info.st_mode) & 0o022)
            except BaseException:
                os.close(child)
                raise
            os.close(parent)
            parent = child
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK |
                     os.O_CLOEXEC, dir_fd=parent)
        info = os.fstat(fd)
        try:
            need(stat.S_ISREG(info.st_mode) and info.st_uid == info.st_gid == 0 and
                 info.st_nlink == 1 and 0 < info.st_size <= maximum and
                 (modes is None or stat.S_IMODE(info.st_mode) in modes))
            return fd
        except BaseException:
            os.close(fd)
            raise
    finally:
        os.close(parent)


def bounded_digest(fd, maximum):
    before = os.fstat(fd)
    need(stat.S_ISREG(before.st_mode) and 0 < before.st_size <= maximum)
    sha = hashlib.sha256()
    count = 0
    while block := os.read(fd, 65536):
        count += len(block)
        need(count <= maximum)
        sha.update(block)
    after = os.fstat(fd)
    need(count == before.st_size and all(getattr(before, key) == getattr(after, key)
                                          for key in ("st_dev", "st_ino", "st_mode", "st_uid",
                                                      "st_gid", "st_nlink", "st_size",
                                                      "st_mtime_ns", "st_ctime_ns")))
    return count, sha.hexdigest()


def bounded_root_bytes(path, maximum, modes=None):
    fd = held_root_file(path, maximum, modes)
    try:
        before = os.fstat(fd)
        raw = os.read(fd, maximum + 1)
        after = os.fstat(fd)
        need(len(raw) == before.st_size and len(raw) <= maximum and
             all(getattr(before, key) == getattr(after, key) for key in
                 ("st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_nlink",
                  "st_size", "st_mtime_ns", "st_ctime_ns")))
        return raw
    finally:
        os.close(fd)


def signed_client_package(public_root, incoming_deb=None):
    """Derive the one package from retained admin manifest, before any Stop."""
    public_root = absolute(str(public_root))
    need(public_root.parent == Path("/var/lib/aegis-auto/releases") and
         re.fullmatch(r"[A-Za-z0-9-]{16,128}", public_root.name))
    root_fd = directory(public_root, 0o700)
    os.close(root_fd)
    manifest = strict_json(bounded_root_bytes(public_root / "bundle.manifest.json",
                                              4 * 1024 * 1024, (0o444,)))
    need(type(manifest) is dict and manifest.get("schema") ==
         "aegis_release_bundle_manifest_v2" and
         manifest.get("distribution") == "private_administrative_operator" and
         type(manifest.get("files")) is list)
    files = manifest["files"]
    need(len(files) == len(set(files)) and len(files) <= 4096 and
         all(type(item) is str for item in files))
    raw_sums = bounded_root_bytes(public_root / "SHA256SUMS", 4 * 1024 * 1024, (0o444,))
    sums = {}
    for line in raw_sums.decode("ascii").splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  ([A-Za-z0-9_./@-]+)", line)
        need(match is not None and match[2] not in sums)
        sums[match[2]] = match[1]
    need(set(sums) == set(files) - {"SHA256SUMS"})
    binaries = manifest.get("binaries")
    need(type(binaries) is dict and type(binaries.get("aegis-client")) is dict and
         binaries["aegis-client"].get("path") == "bin/aegis-client" and
         sums.get("bin/aegis-client") == binaries["aegis-client"].get("sha256") and
         "install.sh" in sums)
    for relative, maximum, modes in (("bin/aegis-client", 512 << 20, (0o555,)),
                                     ("install.sh", 4 << 20, (0o555,))):
        need(hashlib.sha256(bounded_root_bytes(public_root / relative,
                                               maximum, modes)).hexdigest() ==
             sums[relative])
    split_name = "packages/split-deb-packages.manifest.json"
    need(split_name in sums)
    split_raw = bounded_root_bytes(public_root / split_name, 1024 * 1024, (0o444,))
    need(hashlib.sha256(split_raw).hexdigest() == sums[split_name])
    split = strict_json(split_raw)
    need(type(split) is dict and set(split) == {"version", "deb_arch", "packages"} and
         type(split["version"]) is str and
         re.fullmatch(r"[0-9][0-9A-Za-z.+:~-]{0,80}", split["version"]) and
         split["deb_arch"] in ("amd64", "arm64", "armhf") and
         type(split["packages"]) is dict and
         set(split["packages"]) == {"aegis-server", "aegis-client"})
    name = f"aegis-client_{split['version']}_{split['deb_arch']}.deb"
    need(split["packages"]["aegis-client"]["deb_file"] == name)
    package_name = "packages/" + name
    sidecar_name = package_name + ".sha256"
    need(package_name in sums and sidecar_name in sums)
    sidecar = bounded_root_bytes(public_root / sidecar_name, 128, (0o444,))
    need(hashlib.sha256(sidecar).hexdigest() == sums[sidecar_name] and
         sidecar == f"{sums[package_name]}  {name}\n".encode())
    retained = public_root / package_name
    fd = held_root_file(retained, 512 * 1024 * 1024, (0o444,))
    try:
        need(bounded_digest(fd, 512 * 1024 * 1024)[1] == sums[package_name])
    finally:
        os.close(fd)
    if incoming_deb is not None:
        fd = held_root_file(incoming_deb, 512 * 1024 * 1024)
        try:
            need(bounded_digest(fd, 512 * 1024 * 1024)[1] == sums[package_name])
        finally:
            os.close(fd)
    for field, expected in (("Package", "aegis-client"),
                            ("Architecture", split["deb_arch"]),
                            ("Version", split["version"])):
        need(call_output(["/usr/bin/dpkg-deb", "--field", str(retained), field],
                         maximum=1024, timeout=10).decode("ascii").strip() == expected)
    return retained, sums[package_name]


# The protected payload roster is the client half of build-split-deb-packages.sh.
# Keep the focused source contract test aligned with that builder. These are
# the leaves the V2 passive phase can otherwise replace before Prepare.
FRESH_CLIENT_HELPERS = (
    "lib/root-state.sh", "lib/aegis_installer_auto_v2.py",
    "lib/aegis_auto_uninstall_journal.py",
    "lib/aegis_auto_capture.py", "lib/aegis_auto_capture_topology.py",
    "lib/aegis_auto_endpoint.py", "lib/aegis_auto_guard_policy.py",
    "lib/aegis_auto_foreign_policy.py", "lib/aegis_auto_foreign_monitor.py",
    "lib/aegis_auto_ufw_pins.json", "lib/aegis_initrd_policy.py",
    "lib/aegis_initrd_classic.py",
    "lib/aegis_auto_guardian.py", "lib/aegis_auto_guardian_watchdog.py",
    "lib/aegis_auto_terminal_witness.py", "lib/aegis_auto_terminal_boot_store.py",
    "lib/aegis_auto_terminal_register.py", "lib/aegis_auto_boot_transition.py",
    "lib/aegis-auto-terminal-hook",
    "lib/aegis_auto_launch.py", "lib/aegis_auto_native_witness.py",
    "lib/aegis_auto_sink.py", "lib/aegis_auto_trace_rollback.py",
    "lib/aegis_auto_witness_topology.py", "aegis-device-egress-guard.sh",
    "purge-installed-aegis.sh", "aegis-ubuntu-uninstall.sh",
    "aegis-wide-enable.sh", "aegis-wide-disable.sh",
    "aegis-wide-persist-install.sh", "janitor-wide-linux-tproxy.sh",
    "setup-wide-linux-redirect.sh", "setup-wide-linux-tproxy.sh",
    "setup-wide-linux-nfqueue.sh",
)
FRESH_CLIENT_UNITS = (
    "aegis-auto-config.service", "aegis-auto-capture-topology.service",
    "aegis-auto-guardian-watchdog.service", "aegis-auto-guardian.service",
    "aegis-auto-terminal-a@.service", "aegis-auto-terminal-b@.service",
    "aegis-auto-terminal-observer.service",
    "aegis-auto-terminal-transition.service",
    "aegis-auto-trace-rollback-actor.service",
    "aegis-auto-trace-rollback.service", "aegis-auto-trace-rollback.timer",
    "aegis-auto-witness-topology.service",
    "aegis-foreign-policy-monitor.service",
    "aegis-auto-clean-shutdown.service",
    "aegis-device-dhcp-refresh.service",
    "aegis-device-dhcp-refresh.timer",
)


def retained_client_helper_source(root, leaf):
    """Map one protected helper to the exact retained package source."""
    need(leaf in FRESH_CLIENT_HELPERS)
    if leaf == 'lib/aegis-auto-terminal-hook':
        return Path(root) / 'packaging/systemd/system-shutdown/aegis-auto-terminal-hook', 0o500
    mode = (0o500 if leaf.startswith('lib/aegis_auto_') or leaf in
            ('lib/aegis_installer_auto_v2.py','lib/aegis_initrd_policy.py',
             'lib/aegis_initrd_classic.py')
            else 0o755)
    return Path(root) / 'scripts' / leaf, mode


def fresh_package_lock(number, *, allow_uninstall=False):
    """Admit only the shell's original, exclusive InstallLock OFD."""
    need(type(number) is int and 3 <= number <= 1024)
    info = os.fstat(number)
    named = os.stat("/run/aegis-auto-install.lock", follow_symlinks=False)
    need(stat.S_ISREG(info.st_mode) and info.st_uid == info.st_gid == 0 and
         info.st_nlink == 1 and stat.S_IMODE(info.st_mode) == 0o600 and
         (info.st_dev, info.st_ino) == (named.st_dev, named.st_ino))
    lines = [line.split() for line in Path(f"/proc/self/fdinfo/{number}").read_text().splitlines()
             if line.startswith("lock:")]
    need(len(lines) == 1 and len(lines[0]) == 9 and
         lines[0][2:5] == ["FLOCK", "ADVISORY", "WRITE"] and
         lines[0][7:] == ["0", "EOF"])
    match = re.fullmatch(r"([0-9a-fA-F]+):([0-9a-fA-F]+):([0-9]+)", lines[0][6])
    need(match is not None and
         (int(match[1], 16), int(match[2], 16), int(match[3])) ==
         (os.major(info.st_dev), os.minor(info.st_dev), info.st_ino))
    need(allow_uninstall or not uninstall_intent_present())


def uninstall_intent_present():
    """The persistent barrier is outside the control tree being retired."""
    location = Path("/var/lib/aegis-auto-uninstall")
    if not location.exists() and not location.is_symlink():
        return False
    try:
        fd = uninstall_journal.directory()
    except FileNotFoundError:
        return False
    try:
        if uninstall_journal.absent(fd, "intent.json"):
            entries = os.listdir(fd)
            need(all(re.fullmatch(r"(?:pending-intent|failed-[0-9a-f]{32})\.json", name)
                     for name in entries))
            # mkdir itself is durable retirement intent. A cut before its
            # first leaf must fence Python exactly as it already fences Rust
            # and preinst; only typed uninstall replay may fill this namespace.
            return True
        intent = uninstall_journal.strict_json(uninstall_journal.leaf(fd, "intent.json"))
        if intent.get("schema") == uninstall_journal.PASSIVE_SCHEMA:
            uninstall_journal.passive_intent(fd)
        else:
            uninstall_journal.read(fd)
        return True
    finally:
        os.close(fd)


def fresh_pid1_unit(unit, raw, timer=False):
    lines = raw.decode("utf-8", "strict").splitlines()
    keys = [line.split("=", 1)[0] for line in lines]
    need(len(keys) == len(set(keys)) and all("=" in line for line in lines))
    fields = dict(line.split("=", 1) for line in lines)
    expected = {"Id": unit, "LoadState": "not-found" if unit ==
                "aegis-device-egress-guard.service" else "loaded",
                "ActiveState": "inactive", "SubState": "dead"}
    if not timer:
        expected.update({"MainPID": "0", "ControlPID": "0",
                         "ControlGroup": "", "NFileDescriptorStore": "0"})
    need(fields == expected)


def fresh_installed_package(public_root, install_fd):
    """Admit a pristine package A as fresh before any device redemption."""
    _set_phase("lock")
    need(sys.platform == "linux" and os.geteuid() == 0)
    fresh_package_lock(install_fd)
    _set_phase("signed_package")
    root = absolute(public_root)
    package, _ = signed_client_package(root)
    _set_phase("dpkg_status")
    version = call_output(["/usr/bin/dpkg-deb", "--field", str(package), "Version"],
                          maximum=1024, timeout=10).decode("ascii").strip()
    arch = call_output(["/usr/bin/dpkg-deb", "--field", str(package), "Architecture"],
                       maximum=1024, timeout=10).decode("ascii").strip()
    observed = call_output(["/usr/bin/dpkg-query", "--show",
                            "--showformat=${Status}\n${Version}\n${Architecture}\n",
                            "aegis-client"], maximum=1024, timeout=10)
    need(observed == f"install ok installed\n{version}\n{arch}\n".encode())
    if _aborted_package_requires_reapply(install_fd):
        raise FreshPassiveAbortedReapplyRequired()
    _set_phase("dpkg_verify")
    need(call_output(["/usr/bin/dpkg", "--verify", "aegis-client"],
                     maximum=4096, timeout=30) == b"")

    # A package-owned executable alone is the only admissible reason for the
    # generic installer to have classified this machine as an upgrade.
    for index, name in enumerate((
        "/etc/aegis/aegis.toml", "/etc/aegis/client/aegis.toml",
        "/etc/aegis/client/aegis-client.toml",
        "/etc/systemd/system/aegis-client.service",
        "/var/lib/aegis-auto/control/v2-enabled",
        "/var/lib/aegis-auto/control/current.json",
        "/var/lib/aegis-auto/control/prepare-current.json",
        "/var/lib/aegis-auto/control/generation-active-current.json",
        "/var/lib/aegis-auto/control/generation-stopped-current.json",
        "/var/lib/aegis-auto/control/generation-successor-current.json",
        "/var/lib/aegis-install/client/device-guard.conf",
        "/var/lib/aegis-install/client/auto-stage-owner.json",
        "/var/lib/aegis-install/client/auto-watchdog-pending.json",
        "/var/lib/aegis-install/client/auto-stop-intent.json",
        "/var/lib/aegis-install/client/auto-guard-rotation-intent.json",
        "/var/lib/aegis-install/auto-client/wide-profile.json",
        "/etc/systemd/system/aegis-device-egress-guard.service",
        "/etc/aegis-auto-terminal-source.json",
        "/etc/aegis-auto-terminal-store.json",
        "/usr/lib/systemd/system-shutdown/aegis-auto-terminal-hook",
    )):
        _set_phase("absent_path", index)
        path = Path(name)
        need(not path.exists() and not path.is_symlink())
    for index, name in enumerate(("/etc/aegis/client", "/var/lib/aegis-client",
                 "/var/lib/aegis-install/client",
                 "/var/lib/aegis-install/auto-client",
                 "/etc/systemd/system/aegis-client.service.d")):
        _set_phase("empty_dir", index)
        path = Path(name)
        if path.exists() or path.is_symlink():
            fd = directory(path)
            try:
                need(not os.listdir(fd))
            finally:
                os.close(fd)
    _set_phase("snapshots")
    snapshots = Path("/run/aegis-installer-config-snapshots")
    if snapshots.exists() or snapshots.is_symlink():
        info = snapshots.lstat()
        need(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and
             not info.st_mode & 0o022 and next(snapshots.iterdir(), None) is None)
    _set_phase("control")
    control = Path("/var/lib/aegis-auto/control")
    if control.exists() or control.is_symlink():
        fd = control_directory()
        try:
            need(not _passive_names(fd, ()))
        finally:
            os.close(fd)

    paths = [("/usr/local/bin/aegis-client", root / "bin/aegis-client", 0o755)]
    for name in FRESH_CLIENT_HELPERS:
        source, mode = retained_client_helper_source(root, name)
        paths.append(("/usr/local/lib/aegis/helpers/" + name, source, mode))
    for name in FRESH_CLIENT_UNITS:
        paths.append(("/etc/systemd/system/" + name,
                      root / "packaging/systemd" / name, 0o644))
    for index, (installed, source, mode) in enumerate(paths):
        _set_phase("installed_file", index)
        need(call_output(["/usr/bin/dpkg-query", "--search", installed],
                         maximum=1024, timeout=10) ==
             f"aegis-client: {installed}\n".encode())
        fd = held_root_file(installed, 512 << 20, (mode,))
        source_fd = held_root_file(source, 512 << 20, (0o444, 0o555))
        try:
            need(bounded_digest(fd, 512 << 20) == bounded_digest(source_fd, 512 << 20))
        finally:
            os.close(fd)
            os.close(source_fd)
    _set_phase("env")
    environment = bounded_root_bytes(root / "packaging/env/aegis-client.env.example",
                                     1 << 20, (0o444,))
    need(bounded_root_bytes("/etc/default/aegis-client", 1 << 20, (0o644,)) ==
         environment)
    _set_phase("unit_template")
    template = bounded_root_bytes(root / "packaging/systemd/aegis-client.service",
                                  1 << 20, (0o444,)).decode("utf-8", "strict")
    for marker, value, count in (
        ("__AEGIS_CLIENT_ENV_FILE__", "/etc/default/aegis-client", 1),
        ("__AEGIS_CLIENT_STATE_DIR__", "/var/lib/aegis-client", 2),
        ("__AEGIS_CLIENT_BIN__", "/usr/local/bin/aegis-client", 1),
        ("__AEGIS_CLIENT_CONFIG__", "/etc/aegis/client/aegis.toml", 1),
        ("__AEGIS_CLIENT_RUNTIME_EVENTS_JSONL__",
         "/var/log/aegis-client/runtime-events.jsonl", 1)):
        need(template.count(marker) == count)
        template = template.replace(marker, value)
    need("__AEGIS_" not in template and
         bounded_root_bytes("/usr/lib/systemd/system/aegis-client.service",
                            1 << 20, (0o644,)) == template.encode())
    # A successful dpkg postinst presets but does not start any AUTO actor.
    for index, unit in enumerate(("aegis-client.service", "aegis-device-egress-guard.service",
                 "aegis-auto-guardian.service", "aegis-auto-guardian-watchdog.service",
                 "aegis-auto-capture-topology.service", "aegis-auto-witness-topology.service",
                 "aegis-auto-trace-rollback-actor.service", "aegis-auto-trace-rollback.service",
                 "aegis-auto-trace-rollback.timer", "aegis-auto-config.service")):
        _set_phase("unit_state", index)
        timer = unit.endswith(".timer")
        properties = ("Id", "LoadState", "ActiveState", "SubState") + (
            () if timer else ("MainPID", "ControlPID", "ControlGroup", "NFileDescriptorStore"))
        argv = ["/usr/bin/systemctl", "show", unit, "--no-pager"]
        for name in properties:
            argv.extend(("-p", name))
        fresh_pid1_unit(unit, call_output(argv, maximum=4096, timeout=5), timer)
    _set_phase("private_units")
    need(not call_output(["/usr/bin/systemctl", "list-units", "--all", "--plain",
                          "--no-legend", "--no-pager", "aegis-auto@*.service"],
                         maximum=4096, timeout=5).strip())
    _set_phase("jobs")
    jobs = call_output(["/usr/bin/systemctl", "list-jobs", "--plain", "--no-legend",
                        "--no-pager"], maximum=4096, timeout=5).decode()
    need(not any("aegis-" in line for line in jobs.splitlines()))
    _set_phase("lock_final")
    fresh_package_lock(install_fd)
    return "fresh"


def _passive_control(create=False):
    """Open the one durable pre-Prepare namespace through fixed nofollow parents."""
    if create:
        parent = os.open("/var/lib", os.O_RDONLY | os.O_DIRECTORY |
                         os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            for name, mode in (("aegis-auto", 0o700), ("control", 0o700)):
                try:
                    os.mkdir(name, mode, dir_fd=parent)
                    os.fsync(parent)
                except FileExistsError:
                    pass
                child = os.open(name, os.O_RDONLY | os.O_DIRECTORY |
                                os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
                info = os.fstat(child)
                need(stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == 0 and
                     stat.S_IMODE(info.st_mode) == 0o700)
                os.close(parent)
                parent = child
            return parent
        except BaseException:
            os.close(parent)
            raise
    return control_directory()


def _passive_record(parent, leaf):
    try:
        fd = os.open(leaf, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK |
                     os.O_CLOEXEC, dir_fd=parent)
    except FileNotFoundError:
        return None
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_uid == before.st_gid == 0 and
             before.st_nlink == 1 and stat.S_IMODE(before.st_mode) == 0o600 and
             0 < before.st_size <= 16384)
        raw = os.read(fd, 16385)
        after = os.fstat(fd)
        named = os.stat(leaf, dir_fd=parent, follow_symlinks=False)
        fields = ("st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_nlink",
                  "st_size", "st_mtime_ns", "st_ctime_ns")
        need(len(raw) == before.st_size and all(getattr(before, key) ==
             getattr(other, key) for key in fields for other in (after, named)))
        return strict_json(raw)
    finally:
        os.close(fd)


def _passive_write(parent, leaf, value):
    raw = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()
    need(len(raw) <= 16384)
    atomic_exclusive_bytes(parent, leaf, raw, 0o600)
    need(_passive_record(parent, leaf) == value)


def atomic_exclusive_bytes(parent, leaf, raw, mode=0o600):
    """Publish an fsynced leaf atomically without replacing any existing name."""
    need(type(raw) is bytes and 0 < len(raw) <= PASSIVE_FILE_MAX and
         type(leaf) is str and re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", leaf) and
         not leaf.startswith(".") and mode in (0o600, 0o644))
    info = os.fstat(parent)
    need(stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == 0 and
         not stat.S_IMODE(info.st_mode) & 0o022)
    temporary = ".passive-tmp-" + secrets.token_hex(12)
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW |
                 os.O_CLOEXEC, 0o600, dir_fd=parent)
    try:
        os.fchmod(fd, mode)
        written = 0
        while written < len(raw):
            count = os.write(fd, raw[written:])
            need(count > 0)
            written += count
        os.fsync(fd)
    finally:
        os.close(fd)
    libc = ctypes.CDLL(None, use_errno=True)
    rename = libc.renameat2
    rename.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int,
                       ctypes.c_char_p, ctypes.c_uint)
    rename.restype = ctypes.c_int
    if rename(parent, temporary.encode(), parent, leaf.encode(), 1) != 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))
    os.fsync(parent)


def _passive_names(parent, allowed):
    names = os.listdir(parent)
    temps = [name for name in names if re.fullmatch(r"\.passive-tmp-[0-9a-f]{24}", name)]
    need(len(temps) <= 32 and set(names) <= set(allowed) | set(temps))
    for name in temps:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK |
                     os.O_CLOEXEC, dir_fd=parent)
        try:
            info = os.fstat(fd)
            need(stat.S_ISREG(info.st_mode) and info.st_uid == info.st_gid == 0 and
                 info.st_nlink == 1 and stat.S_IMODE(info.st_mode) in (0o600, 0o644) and
                 info.st_size <= PASSIVE_FILE_MAX)
        finally:
            os.close(fd)
    return set(names) - set(temps)


def _passive_assessment_orphans(parent):
    """Admit inert, unpublished assessments only; never select one as authority."""
    names = [name for name in os.listdir(parent)
             if re.fullmatch(r"first-arm\.[A-Za-z0-9]{8}", name)]
    need(len(names) <= 8)
    for name in names:
        stage = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW |
                        os.O_CLOEXEC, dir_fd=parent)
        try:
            info = os.fstat(stage)
            need(stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == 0 and
                 stat.S_IMODE(info.st_mode) == 0o700)
            members = os.listdir(stage)
            need(len(members) <= 4)
            for member in members:
                need(member in ("relay-facts.json", "guard.conf") or
                     re.fullmatch(r"\.aegis-install-[0-9a-f]{32}", member))
                held = os.open(member, os.O_RDONLY | os.O_NOFOLLOW |
                               os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=stage)
                try:
                    leaf = os.fstat(held)
                    need(stat.S_ISREG(leaf.st_mode) and leaf.st_uid == leaf.st_gid == 0 and
                         leaf.st_nlink == 1 and stat.S_IMODE(leaf.st_mode) in (0o600, 0o644) and
                         leaf.st_size <= PASSIVE_FILE_MAX)
                finally:
                    os.close(held)
        finally:
            os.close(stage)
    return set(names)


def _passive_optional(options):
    need(type(options) is dict and set(options) == set(PASSIVE_OPTIONS))
    need(all(value is None or type(value) is str and 0 < len(value) <= 2048
             for value in options.values()))
    need(options["requested_mode"] in (None, "socks-only"))
    return hashlib.sha256(json.dumps(options, sort_keys=True,
                                     separators=(",", ":")).encode()).hexdigest()


def _passive_input_bytes(path, maximum):
    """Read an explicit operator input through held, nonwritable ancestors."""
    path = absolute(str(path))
    sudo = os.environ.get("SUDO_UID", "")
    allowed = {0}
    if sudo.isdecimal() and 0 <= int(sudo) <= 0xffffffff:
        allowed.add(int(sudo))
    parent = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for part in path.parts[1:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW |
                            os.O_CLOEXEC, dir_fd=parent)
            info = os.fstat(child)
            try:
                need(stat.S_ISDIR(info.st_mode) and info.st_uid in allowed and
                     not stat.S_IMODE(info.st_mode) & 0o022)
            except BaseException:
                os.close(child)
                raise
            os.close(parent)
            parent = child
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK |
                     os.O_CLOEXEC, dir_fd=parent)
        try:
            before = os.fstat(fd)
            need(stat.S_ISREG(before.st_mode) and before.st_uid in allowed and
                 before.st_nlink == 1 and not stat.S_IMODE(before.st_mode) & 0o022 and
                 0 < before.st_size <= maximum)
            raw = bytearray()
            while chunk := os.read(fd, min(65536, maximum + 1 - len(raw))):
                raw.extend(chunk)
                need(len(raw) <= maximum)
            after = os.fstat(fd)
            fields = ("st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_nlink",
                      "st_size", "st_mtime_ns", "st_ctime_ns")
            need(len(raw) == before.st_size and all(getattr(before, key) ==
                 getattr(after, key) for key in fields))
            return bytes(raw)
        finally:
            os.close(fd)
    finally:
        os.close(parent)


def _passive_bundle_files(bundle):
    bundle = absolute(str(bundle))
    files = {}
    for leaf in PASSIVE_LEAVES:
        path = bundle / leaf
        try:
            raw = _passive_input_bytes(path, PASSIVE_FILE_MAX)
        except FileNotFoundError:
            need(leaf not in PASSIVE_LEAVES[:2])
            files[leaf] = None
            continue
        files[leaf] = {"size": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
    return files


def _passive_external_refs(bundle, options):
    """Bind every path-valued Rust ReferenceSpec input before passive mutation."""
    values = []
    for leaf in ("aegis-client.toml", "aegis-client-privileged-dns.toml"):
        try:
            raw = _passive_input_bytes(bundle / leaf, PASSIVE_FILE_MAX)
        except FileNotFoundError:
            continue
        config = tomllib.loads(raw.decode("utf-8", "strict"))
        need(type(config) is dict)
        relay = config.get("relay", {})
        need(type(relay) is dict)
        for key in ("ca_cert", "masque_ca_cert", "ech_config_list"):
            if key in relay:
                values.append(relay[key])
        for table, keys in (("inner_tls", ("server_ca", "cert", "key")),
                            ("https_bridge", ("credential_file",)),
                            ("web_response", ("credential_file",))):
            section = relay.get(table, {})
            need(type(section) is dict)
            for key in keys:
                if key in section:
                    values.append(section[key])
    if options["masque_ca"] is not None:
        need(Path(options["masque_ca"]).is_absolute())
        values.append(options["masque_ca"])
    refs = {}
    for value in values:
        need(type(value) is str and value and len(value) <= 4096)
        if value == "__CLIENT_CA_CERT_PATH__":
            continue
        path = Path(value)
        relative = None
        if not path.is_absolute():
            parts = value.split("/")
            need(1 <= len(parts) <= 5 and all(re.fullmatch(
                r"[A-Za-z0-9_.-]{1,128}", part) and part not in (".", "..")
                for part in parts))
            relative = value
            path = bundle / value
        path = absolute(str(path))
        raw = _passive_input_bytes(path, PASSIVE_FILE_MAX)
        refs[str(path)] = {"snapshot_relative": relative, "size": len(raw),
                           "sha256": hashlib.sha256(raw).hexdigest()}
    need(len(refs) <= 32)
    return [{"path": key, **refs[key]} for key in sorted(refs)]


def _passive_identity(public_root, fresh_origin):
    _set_phase("identity")
    root = absolute(str(public_root))
    need(root.parent == Path("/var/lib/aegis-auto/releases") and
         re.fullmatch(r"[A-Za-z0-9-]{16,128}", root.name))
    held = directory(root, 0o700)
    os.close(held)
    if fresh_origin == "packaged":
        _set_phase("signed_package")
        package, package_sha = signed_client_package(root)
        need(package.parent == root / "packages")
        tree_sha = hashlib.sha256(bounded_root_bytes(
            root / "bundle.manifest.json", 4 << 20, (0o444,))).hexdigest()
    else:
        need(fresh_origin == "source-layout" and root.name.startswith("source-"))
        rows = []
        total = 0
        for parent, dirs, files in os.walk(root, followlinks=False):
            relative_parent = Path(parent).relative_to(root)
            need(len(rows) + len(dirs) + len(files) <= 4096)
            for name in dirs:
                child = Path(parent) / name
                fd = directory(child, 0o700)
                os.close(fd)
            for name in files:
                path = Path(parent) / name
                relative = str(relative_parent / name)
                _set_phase("installed_file", len(rows))
                fd = held_root_file(path, 512 << 20, (0o444, 0o555))
                try:
                    size, digest = bounded_digest(fd, 512 << 20)
                finally:
                    os.close(fd)
                total += size
                need(total <= 1 << 30)
                rows.append((relative, digest))
        need(rows and len(rows) <= 4096)
        rows.sort()
        tree_sha = hashlib.sha256(json.dumps(dict(rows), sort_keys=True,
                                  separators=(",", ":")).encode()).hexdigest()
        need(root.name == "source-" + tree_sha)
        package_sha = None
    _set_phase("installed_file", 0)
    candidate_sha = hashlib.sha256(bounded_root_bytes(
        root / "bin/aegis-client", 512 << 20, (0o555,))).hexdigest()
    _set_phase("installed_file", 1)
    installer_sha = hashlib.sha256(bounded_root_bytes(
        root / "install.sh", 4 << 20, (0o555,))).hexdigest()
    return {"public_payload_root": str(root), "fresh_origin": fresh_origin,
            "package_sha256": package_sha,
            "source_tree_sha256": tree_sha,
            "candidate_sha256": candidate_sha,
            "installer_sha256": installer_sha}


def _passive_installed_origin(source, install_fd):
    """Recheck fixed installed package identity on every passive retry."""
    _set_phase("lock")
    fresh_package_lock(install_fd)
    root = Path(source["public_payload_root"])
    if source["fresh_origin"] == "source-layout":
        for index, name in enumerate(("/usr/local/bin/aegis-client", "/etc/default/aegis-client",
                     "/usr/lib/systemd/system/aegis-client.service")):
            _set_phase("absent_path", index)
            path = Path(name)
            need(not path.exists() and not path.is_symlink())
        return
    need(source["fresh_origin"] == "packaged")
    _set_phase("signed_package")
    package, package_sha = signed_client_package(root)
    need(package_sha == source["package_sha256"])
    _set_phase("dpkg_status")
    version = call_output(["/usr/bin/dpkg-deb", "--field", str(package), "Version"],
                          maximum=1024, timeout=10).decode("ascii").strip()
    arch = call_output(["/usr/bin/dpkg-deb", "--field", str(package), "Architecture"],
                       maximum=1024, timeout=10).decode("ascii").strip()
    need(call_output(["/usr/bin/dpkg-query", "--show",
                      "--showformat=${Status}\n${Version}\n${Architecture}\n",
                      "aegis-client"], maximum=1024, timeout=10) ==
         f"install ok installed\n{version}\n{arch}\n".encode())
    _set_phase("installed_file", 0)
    binary = "/usr/local/bin/aegis-client"
    need(call_output(["/usr/bin/dpkg-query", "--search", binary],
                     maximum=1024, timeout=10) == f"aegis-client: {binary}\n".encode())
    fd = held_root_file(binary, 512 << 20, (0o755,))
    try:
        need(bounded_digest(fd, 512 << 20)[1] == source["candidate_sha256"])
    finally:
        os.close(fd)
    _set_phase("env")
    environment = bounded_root_bytes(root / "packaging/env/aegis-client.env.example",
                                     1 << 20, (0o444,))
    need(bounded_root_bytes("/etc/default/aegis-client", 1 << 20, (0o644,)) ==
         environment)
    _set_phase("unit_template")
    template = bounded_root_bytes(root / "packaging/systemd/aegis-client.service",
                                  1 << 20, (0o444,)).decode("utf-8", "strict")
    for marker, value, count in (
        ("__AEGIS_CLIENT_ENV_FILE__", "/etc/default/aegis-client", 1),
        ("__AEGIS_CLIENT_STATE_DIR__", "/var/lib/aegis-client", 2),
        ("__AEGIS_CLIENT_BIN__", binary, 1),
        ("__AEGIS_CLIENT_CONFIG__", "/etc/aegis/client/aegis.toml", 1),
        ("__AEGIS_CLIENT_RUNTIME_EVENTS_JSONL__",
         "/var/log/aegis-client/runtime-events.jsonl", 1)):
        need(template.count(marker) == count)
        template = template.replace(marker, value)
    need("__AEGIS_" not in template and
         bounded_root_bytes("/usr/lib/systemd/system/aegis-client.service",
                            1 << 20, (0o644,)) == template.encode())
    _set_phase("lock_final")
    fresh_package_lock(install_fd)


def _passive_intent_shape(record):
    need(type(record) is dict and set(record) == {
        "schema", "boot_id", "source", "original_bundle", "bundle_files",
        "options_sha256", "external_refs", "fresh_origin"} and
         record["schema"] == "aegis_auto_v2_fresh_passive_intent_v1" and
         record["fresh_origin"] in ("packaged", "source-layout") and
         type(record["source"]) is dict and set(record["source"]) == {
             "public_payload_root", "fresh_origin", "package_sha256", "source_tree_sha256",
             "candidate_sha256", "installer_sha256"} and
         type(record["boot_id"]) is str and
         type(record["original_bundle"]) is str and
         type(record["bundle_files"]) is dict and
         set(record["bundle_files"]) == set(PASSIVE_LEAVES) and
         type(record["external_refs"]) is list and
         type(record["options_sha256"]) is str)
    absolute(record["original_bundle"])
    need(re.fullmatch(r"[0-9a-f]{64}", record["options_sha256"]))
    for leaf in PASSIVE_LEAVES:
        entry = record["bundle_files"][leaf]
        if entry is None:
            need(leaf not in PASSIVE_LEAVES[:2])
        else:
            need(type(entry) is dict and set(entry) == {"size", "sha256"} and
                 type(entry["size"]) is int and 0 < entry["size"] <= PASSIVE_FILE_MAX and
                 type(entry["sha256"]) is str and
                 re.fullmatch(r"[0-9a-f]{64}", entry["sha256"]))
    need(len(record["external_refs"]) <= 32)
    previous = ""
    for ref in record["external_refs"]:
        need(type(ref) is dict and set(ref) == {"path", "snapshot_relative", "size", "sha256"} and
             type(ref["path"]) is str and str(absolute(ref["path"])) == ref["path"] and
             ref["path"] > previous and type(ref["size"]) is int and
             0 < ref["size"] <= PASSIVE_FILE_MAX and type(ref["sha256"]) is str and
             re.fullmatch(r"[0-9a-f]{64}", ref["sha256"]))
        relative = ref["snapshot_relative"]
        need(relative is None or type(relative) is str and
             1 <= len(relative.split("/")) <= 5 and
             all(re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", part) and
                 part not in (".", "..") for part in relative.split("/")) and
             str(Path(record["original_bundle"]) / relative) == ref["path"])
        previous = ref["path"]


def _passive_snapshot(parent, bundle, files, refs):
    try:
        os.mkdir(PASSIVE_INPUT, 0o700, dir_fd=parent)
        os.fsync(parent)
    except FileExistsError:
        pass
    snapshot = os.open(PASSIVE_INPUT, os.O_RDONLY | os.O_DIRECTORY |
                       os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
    try:
        info = os.fstat(snapshot)
        need(stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == 0 and
             stat.S_IMODE(info.st_mode) == 0o700)
        top = {k for k, v in files.items() if v is not None}
        top |= {ref["snapshot_relative"].split("/")[0] for ref in refs
                if ref["snapshot_relative"] is not None}
        need(_passive_names(snapshot, top) <= top)
        for leaf in PASSIVE_LEAVES:
            entry = files[leaf]
            if entry is None:
                continue
            try:
                fd = os.open(leaf, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK |
                             os.O_CLOEXEC, dir_fd=snapshot)
            except FileNotFoundError:
                raw = _passive_input_bytes(bundle / leaf, PASSIVE_FILE_MAX)
                need(len(raw) == entry["size"] and
                     hashlib.sha256(raw).hexdigest() == entry["sha256"])
                atomic_exclusive_bytes(snapshot, leaf, raw, 0o600)
            else:
                os.close(fd)
            raw = bounded_root_bytes(CONTROL / PASSIVE_INPUT / leaf,
                                     PASSIVE_FILE_MAX, (0o600,))
            need(len(raw) == entry["size"] and
                 hashlib.sha256(raw).hexdigest() == entry["sha256"])
        for ref in refs:
            relative = ref["snapshot_relative"]
            if relative is None:
                continue
            path = Path(relative)
            held = os.dup(snapshot)
            try:
                for component in path.parts[:-1]:
                    try:
                        os.mkdir(component, 0o700, dir_fd=held)
                        os.fsync(held)
                    except FileExistsError:
                        pass
                    child = os.open(component, os.O_RDONLY | os.O_DIRECTORY |
                                    os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=held)
                    info = os.fstat(child)
                    need(stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == 0 and
                         stat.S_IMODE(info.st_mode) == 0o700)
                    os.close(held)
                    held = child
                try:
                    os.stat(path.name, dir_fd=held, follow_symlinks=False)
                except FileNotFoundError:
                    need(bundle != CONTROL / PASSIVE_INPUT)
                    raw = _passive_input_bytes(Path(ref["path"]), PASSIVE_FILE_MAX)
                    need(len(raw) == ref["size"] and
                         hashlib.sha256(raw).hexdigest() == ref["sha256"])
                    atomic_exclusive_bytes(held, path.name, raw, 0o600)
                raw = bounded_root_bytes(CONTROL / PASSIVE_INPUT / relative,
                                         PASSIVE_FILE_MAX, (0o600,))
                need(len(raw) == ref["size"] and
                     hashlib.sha256(raw).hexdigest() == ref["sha256"])
            finally:
                os.close(held)
    finally:
        os.close(snapshot)


def passive_intent_locate(install_fd):
    _set_phase("locate_lock")
    fresh_package_lock(install_fd)
    _set_phase("locate_abort_pending")
    need(not PASSIVE_ABORT_PENDING.exists() and
         not PASSIVE_ABORT_PENDING.is_symlink())
    try:
        _set_phase("locate_control")
        parent = _passive_control()
    except FileNotFoundError:
        return {"status": "absent"}
    try:
        _set_phase("locate_intent")
        record = _passive_record(parent, PASSIVE_INTENT)
        if record is None:
            _set_phase("locate_empty")
            need(not _passive_names(parent, ()))
            return {"status": "absent"}
        _set_phase("locate_shape")
        _passive_intent_shape(record)
        _set_phase("locate_boot")
        need(record["boot_id"] == current_boot())
        return {"status": "intent",
                "public_payload_root": record["source"]["public_payload_root"],
                "bundle_dir": record["original_bundle"],
                "snapshot_dir": str(CONTROL / PASSIVE_INPUT),
                "fresh_origin": record["fresh_origin"]}
    finally:
        os.close(parent)


def _passive_gate_dropins(dropins):
    """Admit only the exact gate and its inert interrupted atomic writes."""
    gate = dropins / "00-v2-boot-gate.conf"
    if dropins.exists() or dropins.is_symlink():
        fd = directory(dropins)
        try:
            gate_body = b"[Unit]\nConditionPathExists=!/\n"
            members = os.listdir(fd)
            need(len(members) <= 33)
            for member in members:
                if member == gate.name:
                    continue
                need(re.fullmatch(r"\.passive-tmp-[0-9a-f]{24}", member))
                temporary = os.open(member, os.O_RDONLY | os.O_NOFOLLOW |
                                    os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=fd)
                try:
                    before = os.fstat(temporary)
                    need(stat.S_ISREG(before.st_mode) and before.st_uid == before.st_gid == 0 and
                         before.st_nlink == 1 and stat.S_IMODE(before.st_mode) in
                         (0o600, 0o644) and before.st_size <= len(gate_body))
                    chunks = []
                    total = 0
                    while block := os.read(temporary, len(gate_body) + 1 - total):
                        chunks.append(block)
                        total += len(block)
                        need(total <= len(gate_body))
                    after = os.fstat(temporary)
                    need(total == before.st_size and
                         all(getattr(before, key) == getattr(after, key) for key in
                             ("st_dev", "st_ino", "st_mode", "st_uid", "st_gid",
                              "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns")) and
                         gate_body.startswith(b"".join(chunks)))
                finally:
                    os.close(temporary)
        finally:
            os.close(fd)
    if gate.exists() or gate.is_symlink():
        need(bounded_root_bytes(gate, 128, (0o644,)) ==
             b"[Unit]\nConditionPathExists=!/\n")


def _passive_prefix(parent, source):
    """Refuse unknown pre-Prepare state before any caller replays a copy."""
    orphans = _passive_assessment_orphans(parent)
    _passive_names(parent, (PASSIVE_INTENT, PASSIVE_INPUT, PASSIVE_READY,
                            "v2-enabled", *orphans))
    need(_passive_record(parent, POINTER) is None and
         _passive_record(parent, PREPARE_CURRENT) is None)
    for path in ("/var/lib/aegis-auto/control/generation-active-current.json",
                 "/var/lib/aegis-auto/control/generation-stopped-current.json",
                 "/var/lib/aegis-install/client/device-guard.conf",
                 "/var/lib/aegis-install/client/auto-stop-intent.json",
                 "/var/lib/aegis-install/client/auto-watchdog-pending.json",
                 "/etc/systemd/system/aegis-device-egress-guard.service",
                "/etc/aegis-auto-terminal-source.json",
                "/etc/aegis-auto-terminal-store.json",
                "/usr/lib/systemd/system-shutdown/aegis-auto-terminal-hook",
                 "/etc/systemd/system/aegis-client.service",
                 "/etc/aegis/client/aegis.toml"):
        target = Path(path)
        need(not target.exists() and not target.is_symlink())
    stage_root = Path("/run/aegis-installer-config-snapshots")
    if stage_root.exists() or stage_root.is_symlink():
        fd = directory(stage_root)
        try:
            need(not os.listdir(fd))
        finally:
            os.close(fd)
    marker = CONTROL / "v2-enabled"
    if marker.exists() or marker.is_symlink():
        need(bounded_root_bytes(marker, 128, (0o600,)) ==
             b'{"schema":"aegis_installer_auto_v2_enabled_v1"}\n')
    _passive_gate_dropins(Path("/etc/systemd/system/aegis-client.service.d"))
    for raw in ("/etc/aegis/client", "/var/lib/aegis-client"):
        path = Path(raw)
        if path.exists() or path.is_symlink():
            fd = directory(path)
            try:
                need(not os.listdir(fd))
            finally:
                os.close(fd)
    root = Path(source["public_payload_root"])
    for leaf in FRESH_CLIENT_HELPERS:
        installed = Path("/usr/local/lib/aegis/helpers") / leaf
        if not installed.exists() and not installed.is_symlink():
            continue
        source_path, expected_mode = retained_client_helper_source(root, leaf)
        source_raw = bounded_root_bytes(source_path, 4 << 20,
                                        (0o444, 0o555))
        modes = (0o644, 0o755) if leaf == "lib/root-state.sh" else (expected_mode,)
        need(bounded_root_bytes(installed, 4 << 20, modes) == source_raw)
    for leaf in FRESH_CLIENT_UNITS:
        installed = Path("/etc/systemd/system") / leaf
        if installed.exists() or installed.is_symlink():
            need(bounded_root_bytes(installed, 1 << 20, (0o644,)) ==
                 bounded_root_bytes(root / "packaging/systemd" / leaf,
                                    1 << 20, (0o444,)))
    metadata = Path("/var/lib/aegis-install/client")
    installation = metadata / "auto-guardian-install.json"
    if metadata.exists() or metadata.is_symlink():
        fd = directory(metadata)
        try:
            _passive_names(fd, ("auto-guardian-install.json",))
        finally:
            os.close(fd)
    saved, missing = passive_actor_status()
    if not installation.exists() and not installation.is_symlink():
        need(not saved and len(missing) == len(PASSIVE_ACTORS))
        return "prefix"
    # Provision is a read-only exact-source constructor. No live helper may be
    # replaced after this durable receipt exists, even if all actors are dead.
    for leaf in FRESH_CLIENT_HELPERS:
        need((Path("/usr/local/lib/aegis/helpers") / leaf).exists())
    for leaf in FRESH_CLIENT_UNITS:
        need((Path("/etc/systemd/system") / leaf).exists())
    installed = Path("/usr/local/lib/aegis/helpers/lib/aegis_auto_guardian.py")
    spec = importlib.util.spec_from_file_location("aegis_auto_guardian_passive", installed)
    need(spec is not None and spec.loader is not None)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    candidate = root / "bin/aegis-client"
    observed = module.record(module.INSTALL)
    need(observed == module.provision_receipt(candidate) and
         observed["guard_unit_sha256"] is None)
    module.own_source()
    return "actors-starting"


def _passive_source_fresh(install_fd):
    """Separate source-layout admission; never substitute for failed DEB proof."""
    fresh_package_lock(install_fd)
    for raw in ("/usr/local/bin/aegis-client", "/etc/default/aegis-client",
                "/usr/lib/systemd/system/aegis-client.service",
                "/etc/aegis/client/aegis.toml",
                "/etc/systemd/system/aegis-client.service",
                "/var/lib/aegis-auto/control/v2-enabled",
                "/var/lib/aegis-auto/control/current.json",
                "/var/lib/aegis-auto/control/prepare-current.json",
                "/var/lib/aegis-auto/control/generation-active-current.json",
                "/var/lib/aegis-install/client/auto-guardian-install.json",
                "/var/lib/aegis-install/client/device-guard.conf",
                "/etc/aegis-auto-terminal-source.json",
                "/etc/aegis-auto-terminal-store.json",
                "/usr/lib/systemd/system-shutdown/aegis-auto-terminal-hook",
                "/etc/systemd/system/NetworkManager.service.d/31-aegis-auto-terminal-transition.conf",
                "/etc/systemd/system/systemd-networkd.service.d/31-aegis-auto-terminal-transition.conf",
                "/etc/systemd/system/networking.service.d/31-aegis-auto-terminal-transition.conf",
                "/etc/systemd/system/aegis-auto-guardian.service.d/31-aegis-auto-terminal-transition.conf"):
        path = Path(raw)
        need(not path.exists() and not path.is_symlink())
    for raw in ("/etc/aegis/client", "/var/lib/aegis-client",
                "/var/lib/aegis-install/client", "/var/lib/aegis-install/auto-client"):
        path = Path(raw)
        if path.exists() or path.is_symlink():
            fd = directory(path)
            try:
                need(not os.listdir(fd))
            finally:
                os.close(fd)
    need(pid1_fixed_state() == "root")
    no_private_jobs_or_units()
    _uninstall_terminal_instances_stopped()
    for unit in ("aegis-auto-guardian.service", "aegis-auto-guardian-watchdog.service",
                 "aegis-auto-witness-topology.service",
                 "aegis-auto-trace-rollback-actor.service"):
        raw = call_output(["/usr/bin/systemctl", "show", unit, "-p", "ActiveState",
                           "-p", "SubState", "-p", "MainPID", "-p", "ControlPID"],
                          maximum=1024, timeout=5)
        rows = raw.decode("ascii").splitlines()
        need(len(rows) == 4 and all("=" in row for row in rows))
        facts = dict(row.split("=", 1) for row in rows)
        need(len(facts) == 4 and facts == {"ActiveState": "inactive",
             "SubState": "dead", "MainPID": "0", "ControlPID": "0"})
    fresh_package_lock(install_fd)


def passive_intent_admit(public_root, original_bundle, install_fd, options,
                         fresh_origin,
                         *, create=False):
    """Re-admit source, caller input and the immutable pre-Prepare snapshot."""
    need(sys.platform == "linux" and os.geteuid() == 0)
    fresh_package_lock(install_fd)
    need(fresh_origin in ("packaged", "source-layout"))
    source = _passive_identity(public_root, fresh_origin)
    option_sha = _passive_optional(options)
    bundle = absolute(str(original_bundle))
    snapshot_path = CONTROL / PASSIVE_INPUT
    if create:
        # The package observation must precede the first protected marker.
        if fresh_origin == "packaged":
            fresh_installed_package(str(public_root), install_fd)
        else:
            _passive_source_fresh(install_fd)
    parent = _passive_control(create=create)
    try:
        intent = _passive_record(parent, PASSIVE_INTENT)
        new = intent is None
        if new:
            need(create and not _passive_names(parent, ()) and bundle != snapshot_path)
            files = _passive_bundle_files(bundle)
            refs = _passive_external_refs(bundle, options)
            intent = {"schema": "aegis_auto_v2_fresh_passive_intent_v1",
                      "boot_id": current_boot(), "source": source,
                      "original_bundle": str(bundle), "bundle_files": files,
                      "options_sha256": option_sha, "external_refs": refs,
                      "fresh_origin": fresh_origin}
            _passive_write(parent, PASSIVE_INTENT, intent)
        _passive_intent_shape(intent)
        need(intent["boot_id"] == current_boot() and intent["source"] == source and
             intent["fresh_origin"] == fresh_origin and
             intent["options_sha256"] == option_sha and
             bundle in (Path(intent["original_bundle"]), snapshot_path))
        if bundle != snapshot_path:
            need(_passive_bundle_files(bundle) == intent["bundle_files"] and
                 _passive_external_refs(bundle, options) == intent["external_refs"])
        for ref in intent["external_refs"]:
            path = (snapshot_path / ref["snapshot_relative"] if
                    bundle == snapshot_path and ref["snapshot_relative"] is not None
                    else Path(ref["path"]))
            raw = (_passive_input_bytes(path, PASSIVE_FILE_MAX) if bundle != snapshot_path or
                   ref["snapshot_relative"] is None else
                   bounded_root_bytes(path, PASSIVE_FILE_MAX, (0o600,)))
            need(len(raw) == ref["size"] and
                 hashlib.sha256(raw).hexdigest() == ref["sha256"])
        _passive_snapshot(parent, Path(intent["original_bundle"]) if
                          bundle != snapshot_path else snapshot_path,
                          intent["bundle_files"], intent["external_refs"])
        fresh_package_lock(install_fd)
        _passive_installed_origin(source, install_fd)
        if _passive_record(parent, FIRST_ARM_INTENT) is None:
            _passive_prefix(parent, source)
        else:
            # Root's first-arm verifier owns all stronger guarded phase facts.
            need(_passive_record(parent, POINTER) is None and
                 _passive_record(parent, PREPARE_CURRENT) is None)
        return intent
    finally:
        os.close(parent)


def passive_intent_phase(public_root, original_bundle, install_fd, options,
                         fresh_origin,
                         *, create=False, seal_ready=False):
    deadline = time.monotonic() + (min(10.0, PHASE_TIMEOUT) if seal_ready else 0.0)
    while True:
        try:
            intent = passive_intent_admit(public_root, original_bundle, install_fd,
                                          options, fresh_origin, create=create)
            break
        except (Refused, OSError):
            if not seal_ready or time.monotonic() >= deadline:
                raise
            time.sleep(min(0.1, max(0.0, deadline - time.monotonic())))
    parent = _passive_control()
    try:
        first_arm = _passive_record(parent, FIRST_ARM_INTENT)
        ready = _passive_record(parent, PASSIVE_READY)
        if first_arm is not None:
            # Routing only: first-arm owns the stronger assessment, Stop and
            # guarded source phase. Do not call passive guardian_ready here.
            need(type(first_arm) is dict and
                 first_arm.get("schema") == "aegis_auto_v2_first_arm_intent_v1")
            phase = "first-arm"
        else:
            if seal_ready or ready is not None:
                candidate = Path(intent["source"]["public_payload_root"]) / "bin/aegis-client"
                wait_guardian_ready(candidate, "passive")
                if ready is None:
                    _passive_write(parent, PASSIVE_READY, {
                        "schema": "aegis_auto_v2_fresh_passive_ready_v1",
                        "boot_id": intent["boot_id"],
                        "intent_sha256": hashlib.sha256(bounded_root_bytes(
                            CONTROL / PASSIVE_INTENT, 16384, (0o600,))).hexdigest(),
                        "candidate_sha256": intent["source"]["candidate_sha256"]})
                    ready = _passive_record(parent, PASSIVE_READY)
                need(type(ready) is dict and set(ready) == {
                    "schema", "boot_id", "intent_sha256", "candidate_sha256"} and
                     ready["schema"] == "aegis_auto_v2_fresh_passive_ready_v1" and
                     ready["boot_id"] == intent["boot_id"] and
                     ready["candidate_sha256"] == intent["source"]["candidate_sha256"] and
                     ready["intent_sha256"] == hashlib.sha256(bounded_root_bytes(
                         CONTROL / PASSIVE_INTENT, 16384, (0o600,))).hexdigest())
            phase = ("passive-ready" if ready is not None else
                     _passive_prefix(parent, intent["source"]))
        return {"status": "fresh" if create else "resume", "phase": phase,
                "bundle_dir": str(CONTROL / PASSIVE_INPUT)}
    finally:
        os.close(parent)


def directory(path, mode=None):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    info = os.fstat(fd)
    try:
        need(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and info.st_gid == 0 and
             not stat.S_IMODE(info.st_mode) & 0o022 and
             (mode is None or stat.S_IMODE(info.st_mode) == mode))
        return fd
    except BaseException:
        os.close(fd)
        raise


def control_directory(root="/"):
    """Hold every component of the fixed, root-owned recovery namespace."""
    held = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW |
                   os.O_CLOEXEC)
    try:
        for component in ("var", "lib", "aegis-auto", "control"):
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY |
                            os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=held)
            info = os.fstat(child)
            try:
                need(stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == 0 and
                     not stat.S_IMODE(info.st_mode) & 0o022 and
                     (component != "control" or stat.S_IMODE(info.st_mode) == 0o700))
            except BaseException:
                os.close(child)
                raise
            os.close(held)
            held = child
        return held
    except BaseException:
        os.close(held)
        raise


def current_boot():
    boot = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    need(re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", boot))
    return boot


def current_pointer(parent):
    try:
        fd = os.open(POINTER, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK |
                     os.O_CLOEXEC, dir_fd=parent)
    except FileNotFoundError:
        return None
    try:
        info = os.fstat(fd)
        need(stat.S_ISREG(info.st_mode) and info.st_uid == info.st_gid == 0 and
             stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1 and
             0 < info.st_size <= MAX_REPLY)
        raw = os.read(fd, MAX_REPLY + 1)
        need(len(raw) == info.st_size)
        value = strict_json(raw)
        base = {
            "schema", "stage", "status", "boot_id", "installed_binary",
            "candidate_sha256", "previous_binary"}
        boot_fields = {"boot_intent_sha256", "prepare_intent_sha256",
                       "prepare_completed_sha256"}
        need(type(value) is dict and set(value) ==
             (base | boot_fields if value.get("schema") ==
              "aegis_installer_auto_v2_boot_stage_v3" else base) and
             value["schema"] in ("aegis_installer_auto_v2_stage_v1",
                                   "aegis_installer_auto_v2_stage_v2",
                                   "aegis_installer_auto_v2_boot_stage_v3") and
             value["status"] == "pending" and
             type(value["stage"]) is str and
             absolute(value["stage"]).parent == Path("/run/aegis-installer-config-snapshots") and
             value["installed_binary"] == "/usr/local/bin/aegis-client" and
             type(value["candidate_sha256"]) is str and
             re.fullmatch(r"[0-9a-f]{64}", value["candidate_sha256"]) and
             type(value["boot_id"]) is str and
             (value["schema"] != "aegis_installer_auto_v2_boot_stage_v3" or
              all(type(value[key]) is str and re.fullmatch(r"[0-9a-f]{64}", value[key])
                  for key in boot_fields)))
        old = value["previous_binary"]
        if old is not None:
            v2 = value["schema"] in ("aegis_installer_auto_v2_stage_v2",
                                     "aegis_installer_auto_v2_boot_stage_v3")
            fields = {"name", "sha256", "device", "inode", "size", "mode"}
            need(type(old) is dict and set(old) ==
                 (fields | {"backup_device", "backup_inode"} if v2 else fields) and
                 type(old["name"]) is str and
                 re.fullmatch(r"backup-[0-9a-f]{32}\.bin", old["name"]) and
                 type(old["sha256"]) is str and re.fullmatch(r"[0-9a-f]{64}", old["sha256"]) and
                 all(type(old[field]) is int and old[field] > 0 for field in
                     (("device", "inode", "backup_device", "backup_inode", "size")
                      if v2 else ("device", "inode", "size"))) and
                 type(old["mode"]) is int and old["mode"] in (0o555, 0o755))
            saved = os.open(old["name"], os.O_RDONLY | os.O_NOFOLLOW |
                            os.O_CLOEXEC | os.O_NONBLOCK, dir_fd=parent)
            try:
                backup = os.fstat(saved)
                need(stat.S_ISREG(backup.st_mode) and backup.st_uid == backup.st_gid == 0 and
                     backup.st_nlink == 1 and stat.S_IMODE(backup.st_mode) == 0o600 and
                     (not v2 or
                      ((backup.st_dev, backup.st_ino) ==
                       (old["backup_device"], old["backup_inode"]) and
                       (old["device"], old["inode"]) !=
                       (old["backup_device"], old["backup_inode"]))) and
                     file_sha(saved) == (old["size"], old["sha256"]))
            finally:
                os.close(saved)
        return value, raw, info
    finally:
        os.close(fd)


def control_leaf(parent, name, maximum=4096):
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK |
                 os.O_CLOEXEC, dir_fd=parent)
    try:
        info = os.fstat(fd)
        need(stat.S_ISREG(info.st_mode) and info.st_uid == info.st_gid == 0 and
             stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1 and
             0 < info.st_size <= maximum)
        raw = os.read(fd, maximum + 1)
        need(len(raw) == info.st_size)
        return raw, info
    finally:
        os.close(fd)


def no_prepare_handoff(parent):
    for leaf in (PREPARE_CURRENT, PREPARE_COMPLETED, PREPARE_STAGE_CREATED):
        try:
            fd = os.open(leaf, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK |
                         os.O_CLOEXEC, dir_fd=parent)
        except FileNotFoundError:
            continue
        else:
            os.close(fd)
            raise Refused()


def admitted_prepare_handoff(stage, paths, expected=None, *,
                             check_prepared_header=True):
    parent = control_directory()
    try:
        if expected is None:
            intent_raw, _ = control_leaf(parent, PREPARE_CURRENT)
            complete_raw, _ = control_leaf(parent, PREPARE_COMPLETED)
        else:
            need(type(expected) is tuple and len(expected) == 2 and
                 all(type(raw) is bytes and 0 < len(raw) <= 4096 for raw in expected))
            intent_raw, complete_raw = expected
        intent, complete = strict_json(intent_raw), strict_json(complete_raw)
        boot_handoff = (type(intent) is dict and intent.get("schema") ==
                        "aegis_auto_v2_boot_prepare_handoff_v2")
        need(type(intent) is dict and set(intent) == ({
            "schema", "phase", "boot_id", "stage", "candidate_binary",
            "public_payload_root", "nonce"} |
            ({"boot_intent_sha256"} if boot_handoff else set())) and
             intent["schema"] in ("aegis_auto_v2_prepare_handoff_v1",
                                  "aegis_auto_v2_boot_prepare_handoff_v2") and
             (not boot_handoff or type(intent["boot_intent_sha256"]) is str and
              re.fullmatch(r"[0-9a-f]{64}", intent["boot_intent_sha256"])) and
             intent["phase"] == "intent" and intent["boot_id"] == current_boot() and
             intent["stage"] == str(stage) and
             intent["candidate_binary"] == str(paths["candidate-binary"]) and
             intent["public_payload_root"] == str(paths["public-payload-root"]) and
             type(intent["nonce"]) is str and
             re.fullmatch(r"[0-9a-f]{32}", intent["nonce"]))
        need(type(complete) is dict and set(complete) == ({
            "schema", "phase", "intent_sha256", "stage", "stage_device",
            "stage_inode", "header_sha256", "input_generation",
            "candidate_sha256", "provenance_sha256"} |
            ({"boot_intent_sha256", "stage_created_sha256"}
             if boot_handoff else set())) and
             complete["schema"] == intent["schema"] and
             (not boot_handoff or complete["boot_intent_sha256"] ==
              intent["boot_intent_sha256"]) and
             (not boot_handoff or type(complete["stage_created_sha256"]) is str and
              re.fullmatch(r"[0-9a-f]{64}", complete["stage_created_sha256"])) and
             complete["phase"] == "completed" and
             complete["intent_sha256"] == hashlib.sha256(intent_raw).hexdigest() and
             complete["stage"] == str(stage) and
             all(type(complete[key]) is int and complete[key] > 0 for key in
                 ("stage_device", "stage_inode")) and
             all(type(complete[key]) is str and
                 re.fullmatch(r"[0-9a-f]{64}", complete[key]) for key in
                 ("header_sha256", "input_generation", "candidate_sha256",
                  "provenance_sha256")))
        if boot_handoff:
            created_sha = complete["stage_created_sha256"]
            fixed = archived = None
            try:
                fixed, _ = control_leaf(parent, PREPARE_STAGE_CREATED)
            except FileNotFoundError:
                pass
            try:
                archived, _ = control_leaf(parent,
                    "prepare-archive-" + created_sha + ".json")
            except FileNotFoundError:
                pass
            need((fixed is not None or archived is not None) and
                 (fixed is None or archived is None or fixed == archived))
            created_raw = fixed if fixed is not None else archived
            created = strict_json(created_raw)
            need(hashlib.sha256(created_raw).hexdigest() == created_sha and
                 type(created) is dict and set(created) == {
                     "schema", "prepare_intent_sha256", "boot_intent_sha256",
                     "boot_id", "stage", "stage_device", "stage_inode",
                     "candidate_binary", "public_payload_root"} and
                 created["schema"] == "aegis_auto_v2_boot_stage_created_v1" and
                 created["prepare_intent_sha256"] ==
                     hashlib.sha256(intent_raw).hexdigest() and
                 created["boot_intent_sha256"] == intent["boot_intent_sha256"] and
                 created["boot_id"] == intent["boot_id"] and
                 created["stage"] == intent["stage"] and
                 created["stage_device"] == complete["stage_device"] and
                 created["stage_inode"] == complete["stage_inode"] and
                 created["candidate_binary"] == intent["candidate_binary"] and
                 created["public_payload_root"] == intent["public_payload_root"])
        stage_fd = os.open(stage, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW |
                           os.O_CLOEXEC)
        try:
            info = os.fstat(stage_fd)
            need(stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == 0 and
                 stat.S_IMODE(info.st_mode) == 0o700 and
                 (info.st_dev, info.st_ino) ==
                 (complete["stage_device"], complete["stage_inode"]))
            header = os.open("header.json", os.O_RDONLY | os.O_NOFOLLOW |
                             os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=stage_fd)
            try:
                hinfo = os.fstat(header)
                need(stat.S_ISREG(hinfo.st_mode) and hinfo.st_uid == hinfo.st_gid == 0 and
                     stat.S_IMODE(hinfo.st_mode) == 0o600 and hinfo.st_nlink == 1 and
                     0 < hinfo.st_size <= 1024 * 1024)
                content = os.read(header, 1024 * 1024 + 1)
                need(len(content) == hinfo.st_size and
                     (not check_prepared_header or
                      hashlib.sha256(content).hexdigest() == complete["header_sha256"]))
            finally:
                os.close(header)
        finally:
            os.close(stage_fd)
        return intent_raw, complete_raw
    finally:
        os.close(parent)



def passive_prepared_reference_match(stage, paths, args):
    """Bind normal Prepare to its exact earlier caller options and snapshot."""
    snapshot = CONTROL / PASSIVE_INPUT
    if paths.get("bundle-dir") != snapshot:
        return  # Existing native fixture/upgrade inputs retain their own StageGuard.
    options = {name: getattr(args, name) for name in PASSIVE_OPTIONS}
    verify_passive_prepared_references(stage, paths["public-payload-root"],
                                      options=options, requested_mode=args.requested_mode,
                                      require_passive=True)



def verify_passive_prepared_references(stage, public_root, *, options=None,
                                       requested_mode=None, require_passive=False):
    """Verify sealed passive snapshot references without accepting new inputs.

    Recovery has no new option request. Its protected intent's options digest
    remains the original identity; it cannot be reconstructed from rendered
    defaults. The pointer grants typed rollback only, never a new activation.
    """
    snapshot = CONTROL / PASSIVE_INPUT
    stage_fd = directory(stage, 0o700)
    try:
        header = strict_json(read_private(stage_fd, "header.json", 1 << 20))
        leaves = header.get("leaves")
        need(type(leaves) is dict and type(leaves.get("input/authority.json")) is str)
        raw = read_private(stage_fd, "input/authority.json", 1 << 20)
        need(hashlib.sha256(raw).hexdigest() == leaves["input/authority.json"])
        manifest = strict_json(raw)
        need(type(manifest) is dict and "logical_bundle" in manifest)
        if manifest["logical_bundle"] != str(snapshot):
            need(not require_passive)
            return  # Non-passive input is admitted by the typed Rust StageGuard.
        intent = strict_json(bounded_root_bytes(CONTROL / PASSIVE_INTENT, 16384, (0o600,)))
        _passive_intent_shape(intent)
        need(intent["boot_id"] == current_boot() and
             intent["source"]["public_payload_root"] == str(public_root))
        if options is not None:
            need(_passive_optional(options) == intent["options_sha256"])
        need(header.get("mode") == (requested_mode or header.get("mode")) and
             header.get("plan", {}).get("product_mode") == header.get("mode"))
        refs = manifest.get("references")
        need(type(refs) is list and len(refs) <= 1024)
        expected = {}
        for leaf, entry in intent["bundle_files"].items():
            if entry is not None:
                expected[str(snapshot / leaf)] = entry["sha256"]
        for item in intent["external_refs"]:
            path = (snapshot / item["snapshot_relative"] if
                    item["snapshot_relative"] is not None else Path(item["path"]))
            expected[str(path)] = item["sha256"]
        found = set()
        for index, ref in enumerate(refs):
            need(type(ref) is dict and set(ref) == {
                "stage_bytes", "generation_leaf", "original_path",
                "final_path", "expected_uid"} and
                 ref["stage_bytes"] == f"input/references/{index:04}/bytes" and
                 type(ref["original_path"]) is str and
                 ref["original_path"] in expected and
                 ref["original_path"] not in found)
            leaf = ref["stage_bytes"]
            need(type(leaves.get(leaf)) is str)
            captured = read_private(stage_fd, leaf, PASSIVE_FILE_MAX)
            digest = hashlib.sha256(captured).hexdigest()
            need(digest == leaves[leaf] == expected[ref["original_path"]])
            found.add(ref["original_path"])
        # Every absolute credential reference is mandatory. The fixed bundle
        # CA leaf may be present without a matching Rust ReferenceSpec.
        for item in intent["external_refs"]:
            path = (snapshot / item["snapshot_relative"] if
                    item["snapshot_relative"] is not None else Path(item["path"]))
            need(str(path) in found)
    finally:
        os.close(stage_fd)



def archive_prepare_handoff(expected):
    parent = control_directory()
    try:
        # The exact durable pointer precedes every archive mutation. Both
        # archives are atomic and content addressed. Retire intent first so
        # a crash leaves completion's intent_sha256 as an exact replay locator.
        need(type(expected) is tuple and len(expected) == 2)
        pointer = current_pointer(parent)
        need(pointer is not None)
        intent, completed = map(strict_json, expected)
        need(intent.get("stage") == completed.get("stage") == pointer[0]["stage"] and
             intent.get("boot_id") == pointer[0]["boot_id"] and
             completed.get("candidate_sha256") == pointer[0]["candidate_sha256"] and
             completed.get("intent_sha256") == hashlib.sha256(expected[0]).hexdigest())
        records = list(zip((PREPARE_CURRENT, PREPARE_COMPLETED), expected))
        if intent.get("schema") == "aegis_auto_v2_boot_prepare_handoff_v2":
            need(pointer[0]["schema"] == "aegis_installer_auto_v2_boot_stage_v3" and
                 pointer[0]["prepare_intent_sha256"] ==
                     hashlib.sha256(expected[0]).hexdigest() and
                 pointer[0]["prepare_completed_sha256"] ==
                     hashlib.sha256(expected[1]).hexdigest())
            created_sha = completed["stage_created_sha256"]
            try:
                created_raw, _ = control_leaf(parent, PREPARE_STAGE_CREATED)
            except FileNotFoundError:
                created_raw, _ = control_leaf(parent,
                    "prepare-archive-" + created_sha + ".json")
            need(hashlib.sha256(created_raw).hexdigest() == created_sha)
            records.append((PREPARE_STAGE_CREATED, created_raw))
        originals = []
        for leaf, raw in records:
            archive = "prepare-archive-" + hashlib.sha256(raw).hexdigest() + ".json"
            try:
                again, original = control_leaf(parent, leaf)
            except FileNotFoundError:
                again, _ = control_leaf(parent, archive)
                original = None
            need(again == raw)
            originals.append((leaf, archive, raw, original))
        for leaf, archive, raw, original in originals:
            try:
                saved, _ = control_leaf(parent, archive)
            except FileNotFoundError:
                atomic_exclusive_bytes(parent, archive, raw)
                saved, _ = control_leaf(parent, archive)
            need(saved == raw)
            if original is not None:
                last, identity = control_leaf(parent, leaf)
                need(last == raw and (identity.st_dev, identity.st_ino) ==
                     (original.st_dev, original.st_ino))
        for leaf, archive, raw, original in originals:
            if original is None:
                continue
            last, identity = control_leaf(parent, leaf)
            need(last == raw and (identity.st_dev, identity.st_ino) ==
                 (original.st_dev, original.st_ino))
            os.unlink(leaf, dir_fd=parent)
            os.fsync(parent)
    finally:
        os.close(parent)



def verify_handoff_candidate(complete_raw, candidate_sha):
    complete = strict_json(complete_raw)
    need(type(complete) is dict and complete.get("candidate_sha256") == candidate_sha)


def fixed_lines(proc, maximum, deadline):
    """Read one bounded line without allowing a silent child to hang the owner."""
    fd = proc.stdout.fileno()
    data = bytearray()
    while True:
        remaining = deadline - time.monotonic()
        need(remaining > 0)
        ready, _, _ = select.select([fd], [], [], remaining)
        need(ready)
        chunk = os.read(fd, 1)
        need(chunk)
        if chunk == b"\n":
            return bytes(data)
        data.extend(chunk)
        need(len(data) <= maximum)


def strict_json(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            need(key not in result)
            result[key] = value
        return result
    def nonfinite(_value):
        raise Refused()
    return json.loads(raw, object_pairs_hook=unique, parse_constant=nonfinite)


_BOOT_FAILURE_PHASES = frozenset({
    "deny_readback", "deny_changed", "boot_id_readback", "boot_id_changed",
    "config_readback", "config_changed", "metadata_readback", "metadata_changed",
    "state_readback", "state_changed", "controller_readback", "controller_changed",
    "machine_readback", "machine_changed", "namespace_changed", "source_changed",
    "guard_ack_repeated", "guard_ack_preflight", "guard_ack_send",
    "guard_ack_receive", "guard_ack_reply_shape", "guard_ack_reply_mismatch",
    "guard_ack_postflight",
})


def _closed_boot_failure_phase(raw: bytes) -> str | None:
    """Return only a source-fixed label; never copy child stderr text."""
    if len(raw) != 512 or raw[-1] != 0:
        return None
    prefix = b"AEGIS_AUTO_BOOT_REFUSED phase="
    line = raw.rstrip(b"\0").split(b"\n", 1)[0]
    if line.startswith(prefix):
        label = line[len(prefix):].decode("ascii", errors="ignore")
        if label in _BOOT_FAILURE_PHASES and line == prefix + label.encode():
            return label
    return None


def call_output(argv, maximum=8192, timeout=10.0, pass_fds=(), env=None,
                diagnostic_stderr=False, closed_boot_phase=False):
    need(not (diagnostic_stderr and closed_boot_phase))
    stderr_fd = None
    if closed_boot_phase:
        # A sealed-size anonymous descriptor bounds even a defective child.
        # Only one fixed Rust label is allowed into the parent journal.
        stderr_fd = os.memfd_create("aegis-boot-phase", os.MFD_CLOEXEC |
                                    os.MFD_ALLOW_SEALING)
        try:
            os.ftruncate(stderr_fd, 512)
            fcntl.fcntl(stderr_fd, fcntl.F_ADD_SEALS,
                        fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK)
        except BaseException:
            os.close(stderr_fd)
            raise
    try:
        proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=(stderr_fd if closed_boot_phase else
                                        None if diagnostic_stderr else subprocess.DEVNULL),
                                close_fds=True, pass_fds=pass_fds, env=env)
        try:
            fd = proc.stdout.fileno()
            deadline = time.monotonic() + timeout
            output = bytearray()
            while True:
                remaining = deadline - time.monotonic()
                need(remaining > 0)
                ready, _, _ = select.select([fd], [], [], remaining)
                need(ready)
                chunk = os.read(fd, min(4096, maximum + 1 - len(output)))
                if not chunk:
                    break
                output.extend(chunk)
                need(len(output) <= maximum)
            status = proc.wait(timeout=1)
            if status != 0:
                error = Refused()
                if closed_boot_phase:
                    phase = _closed_boot_failure_phase(os.pread(stderr_fd, 512, 0))
                    if phase is not None:
                        error.boot_failure_phase = phase
                raise error
            return bytes(output)
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait(timeout=5)
            proc.stdout.close()
    finally:
        if stderr_fd is not None:
            os.close(stderr_fd)


def call_line(argv, maximum=MAX_REPLY, timeout=PHASE_TIMEOUT):
    proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL, close_fds=True)
    try:
        value = fixed_lines(proc, maximum, time.monotonic() + timeout)
        need(proc.wait(timeout=max(0.01, timeout)) == 0)
        need(proc.stdout.read(1) == b"")
        return value
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=5)
        proc.stdout.close()


def response(line, expected):
    need(len(line) <= MAX_REPLY)
    value = strict_json(line)
    need(type(value) is dict)
    if expected == "ready":
        need(value == {"status": "ready"})
    elif expected == "ok":
        need(set(value) == {"status", "value"} and value["status"] == "ok" and
             (value["value"] is None or type(value["value"]) is str))
        if type(value["value"]) is str:
            need(len(value["value"]) <= 4096)
    else:
        raise Refused()
    return value.get("value")


START_FAILURE_PHASES = frozenset({
    "identity", "pre_marker", "subscribe", "claim", "post_claim", "submit",
    "submitted_receipt", "post_submit", "wait_job", "lookup", "invocation",
    "hold_main", "manager_recheck", "post_ready", "completed_receipt",
    "job_id_mismatch",
    "job_identity_after",
    "job_identity_before",
    "job_identity_mismatch",
    "job_path_decode",
    "job_path_mismatch",
    "job_process",
    "job_result_assert",
    "job_result_canceled",
    "job_result_decode",
    "job_result_dependency",
    "job_result_failed",
    "job_result_invalid",
    "job_result_once",
    "job_result_other",
    "job_result_skipped",
    "job_result_timeout",
    "job_result_unsupported",
    "job_signal_budget",
    "job_signal_kind",
    "job_signal_path",
    "job_signal_shape",
    "job_unit_decode",
    "job_unit_mismatch",
    "job_wait",
})
START_FAILURE_CAUSES = frozenset({
    "deny_lease", "launch_lease", "installed_source", "owner", "manager",
    "commitment", "claim_once", "submitted_receipt", "completed_receipt",
    "timeout", "permission", "io",
})


def start_failure_diagnostic(value):
    need(type(value) is dict and set(value) == {"phase", "cause", "errno"})
    need(type(value["phase"]) is str and value["phase"] in START_FAILURE_PHASES and
         type(value["cause"]) is str and value["cause"] in START_FAILURE_CAUSES and
         type(value["errno"]) is int and 0 <= value["errno"] <= 4095)
    return dict(value)


CAPTURE_REFUSAL_REASONS = frozenset({
    "refused", "timeout", "os_error", "value_error", "subprocess_error",
    "runtime_error", "unexpected_exception",
})
CAPTURE_REFUSAL_SOURCES = frozenset({
    "unknown", "guardian", "witness", "topology", "rollback", "policy",
    "endpoint", "capture", "capture_topology",
})
BEGIN_CAPTURE_STEPS = frozenset({
    "stage_reopen", "stage_admit", "recipe_restore", "installed_facts",
    "publication_verify", "policy_prepare", "manager_identity",
    "terminal_configure", "terminal_recover_incomplete", "terminal_prepare",
    "guard_handoff",
    "launch_register", "pid1_start", "launch_prove", "launch_record",
    "capture_precheck", "capture_ready", "capture_revalidate", "capture_mark",
    "terminal_activate",
})


def capture_refusal_diagnostic(value):
    need(type(value) is dict and set(value) == {"reason", "source", "line"})
    reason, source, line = value["reason"], value["source"], value["line"]
    need(type(reason) is str and reason in CAPTURE_REFUSAL_REASONS and
         type(source) is str and source in CAPTURE_REFUSAL_SOURCES and
         type(line) is int and
         ((source == "unknown" and line == 0) or
          (source != "unknown" and 1 <= line <= 10_000)))
    return dict(value)


# Closed BindRuntimeService refusal coordinates; the exact list of
# BIND_RUNTIME_STEPS in aegis-client/src/profile_auto_backend.rs.
BIND_RUNTIME_STEPS = frozenset({
    "worker_pin_before", "dispatch", "worker_pin_after",
    "bind_stage_state", "bind_originals", "bind_settings", "bind_runtime_policy",
    "bind_resolve", "bind_reference_owner", "bind_service_user",
    "bind_account_generation", "bind_header_persist", "bind_resolve_again",
    "bind_binding_equal", "bind_account_generation_again",
    "policy_stage_current", "policy_stage_state", "policy_binding", "policy_inputs",
    "policy_inputs_record", "policy_templates", "policy_namespace",
    "policy_original_leaves", "policy_dropins_capture", "policy_render",
    "policy_runtime_mode", "policy_first_arm", "policy_recipe_build",
    "policy_postflight", "policy_recipe_write",
    "policy_compile_template", "policy_compile_identity_mode",
    "policy_compile_dropin_bounds", "policy_compile_boot_gate",
    "policy_compile_unit_template", "policy_compile_unit_render",
    "policy_compile_fulltun_dropin_name", "policy_compile_first_arm_dropins",
    "policy_compile_guard_hook_missing", "policy_compile_guard_hook_unrecognized",
    "policy_compile_fulltun_unit_shape", "policy_compile_first_arm_entry",
    "policy_compile_other",
})


def begin_capture_step(value):
    need(type(value) is str and value in BEGIN_CAPTURE_STEPS)
    return value


def bind_runtime_step(value):
    need(type(value) is str and value in BIND_RUNTIME_STEPS)
    return value


def worker_phase_deadline(words, started, now):
    # The two packet proofs and their revalidation share one coordinator IPC
    # response. This changes only that response wait; guardian/worker and
    # packet-effect deadlines remain independently enforced.
    timeout = (BEGIN_CAPTURE_TIMEOUT if words == ["begin-capture"]
               else PHASE_TIMEOUT)
    return min(now + timeout, started + WORKER_TIMEOUT)


def worker_phase(proc, words, started, *, phase=None):
    need(proc.poll() is None and type(words) is list and
         all(type(w) is str and 0 < len(w) <= 4096 for w in words))
    frame = json.dumps({"command": words}, separators=(",", ":")).encode() + b"\n"
    need(len(frame) <= 16384)
    proc.stdin.write(frame)
    proc.stdin.flush()
    line = fixed_lines(proc, MAX_REPLY,
                       worker_phase_deadline(words, started, time.monotonic()))
    parsed = strict_json(line)
    need(type(parsed) is dict)
    if parsed.get("status") == "error":
        need(set(parsed) in ({"status", "reason"}, {"status", "reason", "diagnostic"},
                             {"status", "reason", "reload_failure"},
                             {"status", "reason", "capture_refusal"},
                             {"status", "reason", "begin_capture_step"},
                             {"status", "reason", "begin_capture_step", "diagnostic"},
                             {"status", "reason", "begin_capture_step", "capture_refusal"},
                             {"status", "reason", "bind_runtime_step"}) and
             parsed["reason"] in REASONS)
        error = Refused()
        step_value = None
        bind_step_value = None
        if "begin_capture_step" in parsed:
            need(words == ["begin-capture"] and parsed["reason"] in (
                "phase_refused", "native_recovery_required",
                "activation_owner_unavailable", "projection_semantics_changed"))
            step_value = begin_capture_step(parsed["begin_capture_step"])
        if "bind_runtime_step" in parsed:
            # A typed generic refusal of the exact bind command only; it adds
            # a closed coordinate and never changes the refusal itself.
            bind_command = (len(words) == 3 and
                            words[:2] == ["bind-runtime-service", "--service-user"])
            capture_pin = (words == ["begin-capture"] and
                           parsed["bind_runtime_step"] in
                           ("worker_pin_before", "worker_pin_after"))
            need((bind_command or capture_pin) and
                 parsed["reason"] == "phase_refused")
            bind_step_value = bind_runtime_step(parsed["bind_runtime_step"])
        if "reload_failure" in parsed:
            need(phase == 'reload_policy' and words == ['reload-service-policy'] and
                 parsed['reason'] == 'phase_refused' and
                 type(parsed['reload_failure']) is str and
                 parsed['reload_failure'] in RELOAD_FAILURES)
            error.reload_failure = parsed['reload_failure']
        if "diagnostic" in parsed:
            need(parsed["reason"] == "native_recovery_required" and
                 words[0] == "begin-capture" and
                 ("begin_capture_step" not in parsed or
                  parsed["begin_capture_step"] == "pid1_start"))
            error.worker_diagnostic = start_failure_diagnostic(parsed["diagnostic"])
        if "capture_refusal" in parsed:
            need(words == ["begin-capture"] and parsed["reason"] == "phase_refused" and
                 ("begin_capture_step" not in parsed or
                  parsed["begin_capture_step"] == "capture_ready"))
            error.capture_refusal = capture_refusal_diagnostic(parsed["capture_refusal"])
        if step_value is not None:
            error.begin_capture_step = step_value
        if bind_step_value is not None:
            error.bind_runtime_step = bind_step_value
        raise error
    return response(line, "ok")


def pid1_fixed_state():
    line = call_output(["/usr/bin/systemctl", "show", "aegis-client.service",
                      "-p", "LoadState", "-p", "ActiveState", "-p", "SubState",
                      "-p", "MainPID", "-p", "ControlPID", "-p", "ControlGroup",
                      "-p", "User", "-p", "Group", "-p", "NeedDaemonReload"],
                       timeout=10)
    values = {}
    for item in line.decode("ascii").splitlines():
        key, sep, value = item.partition("=")
        need(sep and key not in values)
        values[key] = value
    need(set(values) == {"LoadState", "ActiveState", "SubState", "MainPID",
                         "ControlPID", "ControlGroup", "User", "Group", "NeedDaemonReload"})
    need(values["LoadState"] in ("loaded", "not-found") and
         values["ActiveState"] == "inactive" and values["SubState"] == "dead" and
         values["MainPID"] == "0" and values["ControlPID"] == "0" and
         values["ControlGroup"] == "" and values["NeedDaemonReload"] == "no")
    if values["LoadState"] == "not-found":
        need(values["User"] == values["Group"] == "")
        return "root"
    need(values["User"] in ("", "root", "aegis", "aegis-svc") and
         values["Group"] in ("", "root", "aegis", "aegis-svc"))
    return values["User"] or "root"


def file_sha(fd):
    digest = hashlib.sha256()
    size = 0
    while True:
        chunk = os.read(fd, 65536)
        if not chunk:
            break
        size += len(chunk)
        need(size <= 256 * 1024 * 1024)
        digest.update(chunk)
    return size, digest.hexdigest()


def read_private(stage_fd, relative, maximum):
    parts = relative.split("/")
    need(parts and all(part and part not in (".", "..") for part in parts))
    parent = os.dup(stage_fd)
    try:
        for part in parts[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW |
                            os.O_CLOEXEC, dir_fd=parent)
            info = os.fstat(child)
            need(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and
                 not stat.S_IMODE(info.st_mode) & 0o022)
            os.close(parent)
            parent = child
        child = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK |
                        os.O_CLOEXEC, dir_fd=parent)
        try:
            info = os.fstat(child)
            need(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1 and
                 not stat.S_IMODE(info.st_mode) & 0o077 and 0 <= info.st_size <= maximum)
            data = bytearray()
            while len(data) <= maximum:
                chunk = os.read(child, min(65536, maximum + 1 - len(data)))
                if not chunk:
                    break
                data.extend(chunk)
            need(len(data) == info.st_size and len(data) <= maximum)
            return bytes(data)
        finally:
            os.close(child)
    finally:
        os.close(parent)


def active_properties(unit):
    fields = ("Id", "LoadState", "ActiveState", "SubState", "MainPID", "ControlPID",
              "ControlGroup", "InvocationID", "ExecMainStartTimestampMonotonic", "User",
              "Group", "Type", "NotifyAccess", "StatusText")
    argv = ["/usr/bin/systemctl", "show", unit]
    for field in fields:
        argv.extend(("-p", field))
    raw = call_output(argv, maximum=8192, timeout=10)
    result = {}
    for line in raw.decode("ascii").splitlines():
        key, sep, value = line.partition("=")
        need(sep and key not in result)
        result[key] = value
    need(set(result) == set(fields))
    return result


def actor_socket_owner(path, pid):
    parent = directory(path.parent, 0o700)
    try:
        info = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
        need(stat.S_ISSOCK(info.st_mode) and info.st_uid == 0 and
             stat.S_IMODE(info.st_mode) & 0o077 == 0)
    finally:
        os.close(parent)
    with open("/proc/net/unix", "rb", buffering=0) as source:
        table = read_unix_table(source)
    matches = unix_table_socket_inodes(table, path)
    need(len(matches) == 1)
    fds = Path(f"/proc/{pid}/fd")
    names = list(fds.iterdir())
    need(len(names) <= 1024)
    target = f"socket:[{matches[0]}]"
    owned = False
    for name in names:
        if not name.name.isdecimal():
            continue
        try:
            if os.readlink(name) == target:
                owned = True
                break
        except FileNotFoundError:
            continue  # Another temporary FD closed while the authority FD remains.
    need(owned)


def unix_table_socket_inodes(table, path):
    matches = []
    for line in table.decode("ascii").splitlines()[1:]:
        columns = line.split()
        if len(columns) == 8 and columns[7] == str(path):
            need(columns[6].isdecimal())
            matches.append(columns[6])
    return matches


def read_unix_table(source):
    """Read the bounded proc table to EOF; RawIO reads may stop at a page."""
    maximum = 1024 * 1024
    chunks = []
    total = 0
    while total <= maximum:
        chunk = source.read(min(65536, maximum + 1 - total))
        if not chunk:
            return b"".join(chunks)
        total += len(chunk)
        need(total <= maximum)
        chunks.append(chunk)
    raise Refused("proc_unix_table_too_large")


def _remaining(deadline, cap):
    if deadline is None:
        return cap
    value = min(cap, deadline - time.monotonic())
    need(value > 0)
    return value


def no_private_jobs_or_units(deadline=None):
    units = call_output(["/usr/bin/systemctl", "list-units", "--all", "--type=service",
                         "--no-legend", "--plain", "aegis-auto@*.service"],
                        maximum=65536, timeout=_remaining(deadline, 5))
    for line in units.decode("ascii").splitlines():
        words = line.split()
        need(words and re.fullmatch(r"aegis-auto@[0-9a-f]{64}\.service", words[0]))
        need(len(words) >= 4 and words[2:4] == ["inactive", "dead"])
    jobs = call_output(["/usr/bin/systemctl", "list-jobs", "--no-legend", "--plain"],
                       maximum=65536, timeout=_remaining(deadline, 5))
    need(not any(b"aegis-auto@" in line or b"aegis-auto-guardian" in line
                 for line in jobs.splitlines()))


def local_account_nss(data):
    nss = {}
    need(len(data) <= 1024 * 1024 and
         all(value in (9, 10, 13) or 32 <= value <= 126 for value in data))
    for raw in data.decode("ascii").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        need(not raw[:1].isspace() and not raw.endswith("\\"))
        key, sep, providers = line.partition(":")
        need(sep)
        if key.strip() in ("passwd", "group", "initgroups"):
            need(key == key.strip())
            tokens = providers.split()
            tokens = tokens[:next((i for i, token in enumerate(tokens)
                                   if token.startswith("#")), len(tokens))]
            need(key not in nss and tokens in (["files"], ["files", "systemd"]))
            nss[key] = True
    need(nss.get("passwd") and nss.get("group"))


_RUNTIME_NSS_QUERY = r'''import grp,json,os,pwd
try:
    user=pwd.getpwnam("aegis-svc")
except KeyError:
    try:
        grp.getgrnam("aegis-svc")
    except KeyError:
        print('{"status":"absent"}')
    else:
        print('{"status":"orphan-group"}')
else:
    group=grp.getgrnam("aegis-svc")
    reverse_user=pwd.getpwuid(user.pw_uid)
    reverse_group=grp.getgrgid(group.gr_gid)
    value={"status":"present","name":user.pw_name,"uid":user.pw_uid,
           "gid":user.pw_gid,"home":user.pw_dir,"shell":user.pw_shell,
           "group_name":group.gr_name,"group_gid":group.gr_gid,
           "members":group.gr_mem,"reverse_user":reverse_user.pw_name,
           "reverse_group":reverse_group.gr_name,
           "groups":os.getgrouplist("aegis-svc",user.pw_gid)}
    print(json.dumps(value,separators=(",",":")))
'''


def runtime_nss_record():
    """Bound every glibc NSS lookup, including the configured systemd provider."""
    nss_before = bounded_root_bytes("/etc/nsswitch.conf", 1024 * 1024)
    local_account_nss(nss_before)
    value = strict_json(call_output(["/usr/bin/python3", "-I", "-B", "-c",
                                     _RUNTIME_NSS_QUERY], maximum=2048, timeout=3,
                                    env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
                                         "LANG": "C", "LC_ALL": "C"}))
    need(bounded_root_bytes("/etc/nsswitch.conf", 1024 * 1024) == nss_before)
    need(type(value) is dict and value.get("status") in ("absent", "present"))
    need(value == {"status": "absent"} or set(value) == {
        "status", "name", "uid", "gid", "home", "shell", "group_name",
        "group_gid", "members", "reverse_user", "reverse_group", "groups"})
    return value


def local_runtime_account(record, state_dir):
    """A named NSS result is authority only when unique local files agree."""
    need(record["status"] == "present" and
         record["name"] == record["reverse_user"] == "aegis-svc" and
         record["group_name"] == record["reverse_group"] == "aegis-svc" and
         type(record["uid"]) is int and type(record["gid"]) is int and
         type(record["group_gid"]) is int and
         0 < record["uid"] < 1000 and 0 < record["gid"] < 1000 and
         record["gid"] == record["group_gid"] and
         record["home"] == str(state_dir) and
         record["shell"] == "/usr/sbin/nologin" and
         record["members"] == [] and record["groups"] == [record["gid"]])
    passwd = bounded_root_bytes("/etc/passwd", 1024 * 1024, (0o644,))
    groups = bounded_root_bytes("/etc/group", 1024 * 1024, (0o644,))
    rows = [line.split(":") for line in passwd.decode("utf-8").splitlines()
            if line and not line.startswith("#")]
    def decimal(value):
        need(re.fullmatch(r"[0-9]+", value) is not None)
        number = int(value)
        need(number <= 0xffffffff)
        return number
    need(all(len(row) == 7 for row in rows))
    accounts = [(row, decimal(row[2]), decimal(row[3])) for row in rows]
    own = [entry for entry in accounts if entry[0][0] == "aegis-svc"]
    need(len(own) == 1 and own[0][1:] == (record["uid"], record["gid"]) and
         own[0][0][5:] == [str(state_dir), "/usr/sbin/nologin"] and
         all(row[0] == "aegis-svc" or uid != record["uid"]
             for row, uid, _gid in accounts) and
         all(row[0] == "aegis-svc" or gid != record["gid"] or
             (row[0] == "root" and uid == 0) for row, uid, gid in accounts))
    group_rows = [line.split(":") for line in groups.decode("utf-8").splitlines()
                  if line and not line.startswith("#")]
    need(all(len(row) == 4 for row in group_rows))
    group_entries = [(row, decimal(row[2])) for row in group_rows]
    named = [entry for entry in group_entries if entry[0][0] == "aegis-svc"]
    need(len(named) == 1 and named[0][1] == record["gid"] and
         named[0][0][3] == "" and
         all(row[0] == "aegis-svc" or gid != record["gid"]
             for row, gid in group_entries) and
         all("aegis-svc" not in row[3].split(",") for row in group_rows
             if row[0] != "aegis-svc"))


def runtime_account_preflight(state_dir):
    need(state_dir == Path("/var/lib/aegis-client"))
    record = runtime_nss_record()
    if record["status"] == "absent":
        passwd = bounded_root_bytes("/etc/passwd", 1024 * 1024, (0o644,))
        groups = bounded_root_bytes("/etc/group", 1024 * 1024, (0o644,))
        need(not any(line.split(b":", 1)[0] == b"aegis-svc"
                     for line in passwd.splitlines()) and
             not any(line.split(b":", 1)[0] == b"aegis-svc"
                     for line in groups.splitlines()))
        executable = os.stat("/usr/sbin/useradd", follow_symlinks=False)
        need(stat.S_ISREG(executable.st_mode) and executable.st_uid == 0 and
             not executable.st_mode & 0o022 and executable.st_mode & 0o111)
        return False
    local_runtime_account(record, state_dir)
    return True


def runtime_account_identity(state_dir):
    record = runtime_nss_record()
    local_runtime_account(record, state_dir)
    return record["uid"], record["gid"]


def ensure_runtime_account(state_dir):
    """Create only the fixed service account; Rust binds its captured NSS generation."""
    if not runtime_account_preflight(state_dir):
        need(call_output(["/usr/sbin/useradd", "--system", "--user-group", "--no-create-home",
                          "--home-dir", str(state_dir), "--shell", "/usr/sbin/nologin",
                          "aegis-svc"], maximum=1024, timeout=15) == b"")
    runtime_account_identity(state_dir)


AUTO_RUNTIME_EVENTS = Path("/var/lib/aegis-client-logs/runtime/runtime-events.jsonl")
AUTO_ROOT_RUNTIME_EVENTS = Path("/var/lib/aegis-client-logs/root/runtime-events.jsonl")
AUTO_SERVICE_RUNTIME_EVENTS = Path("/var/lib/aegis-client-logs/service/runtime-events.jsonl")


def selected_runtime_events(path, service_user):
    need(service_user in ("root", "aegis-svc"))
    if path != AUTO_RUNTIME_EVENTS:
        return path
    return (AUTO_ROOT_RUNTIME_EVENTS if service_user == "root"
            else AUTO_SERVICE_RUNTIME_EVENTS)


def prepared_runtime_events(worker, requested, service_user, started):
    """Read the prepared alias resolution before account or log mutation."""
    expected = selected_runtime_events(requested, service_user)
    if requested != AUTO_RUNTIME_EVENTS:
        return expected
    actual = absolute(worker_phase(
        worker, ["inspect", "--field", "runtime-events-path"], started))
    need(actual == expected)
    return actual


def ensure_runtime_events_directory(path, service_user):
    """Admit the fixed writable log directory without touching sealed state."""
    need(path in (Path("/dev/null"), AUTO_ROOT_RUNTIME_EVENTS,
                  AUTO_SERVICE_RUNTIME_EVENTS,
                  Path("/var/log/aegis-client/runtime/runtime-events.jsonl")))
    if path == Path("/dev/null"):
        return
    need(path != AUTO_ROOT_RUNTIME_EVENTS or service_user == "root")
    need(path != AUTO_SERVICE_RUNTIME_EVENTS or service_user == "aegis-svc")
    if service_user == "root":
        uid = gid = 0
    else:
        need(service_user == "aegis-svc")
        uid, gid = runtime_account_identity(Path("/var/lib/aegis-client"))
    # Runtime output has its own protected sibling, outside sealed/mutable
    # client state. Keep the same strict ancestor policy for legacy log paths.
    protected_logs = path in (AUTO_ROOT_RUNTIME_EVENTS, AUTO_SERVICE_RUNTIME_EVENTS)
    log_root = directory("/var/lib" if protected_logs else "/var/log")
    parent_name = "aegis-client-logs" if protected_logs else "aegis-client"
    runtime_name = ("root" if path == AUTO_ROOT_RUNTIME_EVENTS else
                    "service" if path == AUTO_SERVICE_RUNTIME_EVENTS else "runtime")
    try:
        created_parent = False
        try:
            os.mkdir(parent_name, 0o755, dir_fd=log_root)
            created_parent = True
        except FileExistsError:
            pass
        parent = os.open(parent_name, os.O_RDONLY | os.O_DIRECTORY |
                         os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=log_root)
        try:
            if created_parent:
                os.fchmod(parent, 0o755)
                os.fsync(parent)
                os.fsync(log_root)
            pinfo = os.fstat(parent)
            need(stat.S_ISDIR(pinfo.st_mode) and pinfo.st_uid == pinfo.st_gid == 0 and
                 stat.S_IMODE(pinfo.st_mode) == 0o755)
            created_runtime = False
            try:
                os.mkdir(runtime_name, 0o700, dir_fd=parent)
                created_runtime = True
            except FileExistsError:
                pass
            held = os.open(runtime_name, os.O_RDONLY | os.O_DIRECTORY |
                           os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
            try:
                if created_runtime:
                    os.fchown(held, uid, gid)
                    os.fchmod(held, 0o700)
                    os.fsync(held)
                    os.fsync(parent)
                info = os.fstat(held)
                need(stat.S_ISDIR(info.st_mode) and info.st_uid == uid and
                     info.st_gid == gid and stat.S_IMODE(info.st_mode) == 0o700)
                try:
                    fd = os.open("runtime-events.jsonl", os.O_RDONLY | os.O_NOFOLLOW |
                                 os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=held)
                except FileNotFoundError:
                    return
                try:
                    item = os.fstat(fd)
                    need(stat.S_ISREG(item.st_mode) and item.st_uid == uid and
                         item.st_gid == gid and item.st_nlink == 1 and
                         not stat.S_IMODE(item.st_mode) & 0o022)
                finally:
                    os.close(fd)
            finally:
                os.close(held)
        finally:
            os.close(parent)
    finally:
        os.close(log_root)


PASSIVE_ACTORS = (
    ("aegis-auto-guardian.service", "/run/aegis-auto-guard/authority.sock",
     "aegis_auto_guardian.py"),
    ("aegis-auto-guardian-watchdog.service",
     "/run/aegis-auto-guardian-watchdog/authority.sock",
     "aegis_auto_guardian_watchdog.py"),
    ("aegis-auto-witness-topology.service", "/run/aegis-auto-topology/authority.sock",
     "aegis_auto_witness_topology.py"),
    ("aegis-auto-trace-rollback-actor.service", "/run/aegis-auto-rollback/authority.sock",
     "aegis_auto_trace_rollback.py"),
)


def passive_actor_status(deadline=None, *, retired_guardian_invocation=None):
    """Classify each fixed actor; a live one must own its exact source socket."""
    if retired_guardian_invocation is not None:
        need(type(retired_guardian_invocation) is str and
             re.fullmatch(r"[0-9a-f]{32}", retired_guardian_invocation) and
             retired_guardian_invocation != "0" * 32)
    no_private_jobs_or_units(deadline)
    saved = []
    missing = []
    for unit, socket_path, source_name in PASSIVE_ACTORS:
        argv = ["/usr/bin/systemctl", "show", unit, "-p", "Id", "-p", "LoadState",
                "-p", "ActiveState", "-p", "SubState", "-p", "MainPID",
                "-p", "ControlPID", "-p", "ControlGroup", "-p", "InvocationID",
                "-p", "NeedDaemonReload", "-p", "NFileDescriptorStore"]
        raw = call_output(argv, maximum=4096, timeout=_remaining(deadline, 5))
        facts = {}
        for line in raw.decode("ascii").splitlines():
            key, sep, value = line.partition("=")
            need(sep and key not in facts)
            facts[key] = value
        need(set(facts) == {"Id", "LoadState", "ActiveState", "SubState", "MainPID",
                            "ControlPID", "ControlGroup", "InvocationID", "NeedDaemonReload",
                            "NFileDescriptorStore"} and facts["Id"] == unit and
             facts["LoadState"] in ("loaded", "not-found") and
             facts["NeedDaemonReload"] == "no" and
             facts["ControlPID"] == "0" and facts["NFileDescriptorStore"] == "0")
        if facts["ActiveState"] == "inactive":
            need(facts["SubState"] == "dead" and facts["MainPID"] == "0" and
                 facts["ControlGroup"] == "" and
                 (facts["InvocationID"] in ("", "0" * 32) or
                  (unit == "aegis-auto-guardian.service" and
                   facts["LoadState"] == "loaded" and
                   facts["InvocationID"] == retired_guardian_invocation)))
            missing.append(unit)
            continue
        need(facts["LoadState"] == "loaded" and facts["ActiveState"] == "active" and
             facts["SubState"] == "running" and
             facts["ControlGroup"] == "/system.slice/" + unit and
             re.fullmatch(r"[0-9a-fA-F]{32}", facts["InvocationID"]))
        pid = int(facts["MainPID"])
        need(pid > 1 and Path(f"/proc/{pid}/cgroup").read_text() ==
             "0::/system.slice/" + unit + "\n")
        with open(f"/proc/{pid}/cmdline", "rb", buffering=0) as process:
            command = process.read(1025)
        need(command == ("/usr/bin/python3\0-I\0-B\0/usr/local/lib/aegis/helpers/lib/" +
                         source_name + "\0serve\0").encode())
        handle = os.pidfd_open(pid, 0)
        try:
            poller = select.poll()
            poller.register(handle, select.POLLIN | select.POLLHUP | select.POLLERR)
            need(not poller.poll(0))
        finally:
            os.close(handle)
        actor_socket_owner(Path(socket_path), pid)
        saved.append((unit, socket_path, facts))
    return saved, missing


def installed_guardian():
    """Keep one checked guardian/dependency identity throughout this process.

    The receipt changes during passive-to-guarded admission; executable source
    may not. Each consumer still calls own_source for its required phase.
    """
    global _GUARDIAN_CACHE
    name = 'aegis_auto_guardian_preflight'
    with _GUARDIAN_CACHE_LOCK:
        raw = bounded_root_bytes(INSTALLED_GUARDIAN, 1 << 20, (0o500,))
        sha = hashlib.sha256(raw).hexdigest()
        if _GUARDIAN_CACHE is not None:
            path, previous_sha, module = _GUARDIAN_CACHE
            need(path == INSTALLED_GUARDIAN and previous_sha == sha and
                 sys.modules.get(name) is module)
            return module
        need(name not in sys.modules)
        module = types.ModuleType(name)
        module.__file__ = str(INSTALLED_GUARDIAN)
        sys.modules[name] = module
        try:
            exec(compile(raw, str(INSTALLED_GUARDIAN), 'exec', dont_inherit=True),
                 module.__dict__)
        except BaseException:
            if sys.modules.get(name) is module:
                del sys.modules[name]
            raise
        _GUARDIAN_CACHE = (INSTALLED_GUARDIAN, sha, module)
        return module


def guardian_ready(candidate, required=None, deadline=None):
    """Observe the pre-provisioned native deny actors and installed policy."""
    saved, missing = passive_actor_status(deadline)
    need(not missing)
    candidate_fd = os.open(candidate, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        candidate_sha = file_sha(candidate_fd)[1]
    finally:
        os.close(candidate_fd)
    module = installed_guardian()
    module.own_source()
    receipt = module.record(module.INSTALL)
    need(receipt.get("worker_sha256") == candidate_sha)
    need(not module.STOP_INTENT.exists() and not module.STOP_INTENT.is_symlink())
    guarded = receipt.get("guard_unit_sha256") is not None
    need(required is None or guarded == (required == "guarded"))
    if guarded:
        # A later deny re-render cannot erase an earlier monitor refusal.
        # Reject dangling links as well as a durable sticky incident record.
        drift = module.INSTALL.parent / "foreign-policy-drift.json"
        need(not drift.exists() and not drift.is_symlink())
        policy = module.record(module.POLICY)
        state, projection = module._semantic_policy_readback(
            deadline=time.monotonic() + _remaining(deadline, 5))
        need(set(policy) == {"schema", "boot_id", "netns_ino", "guard_dev",
                             "guard_ino", "state_sha256", "policy_sha256"} and
             policy.get("schema") == "aegis_auto_guardian_policy_v1" and
             policy.get("boot_id") == current_boot() and
             policy.get("netns_ino") == os.stat("/proc/self/ns/net").st_ino and
             policy.get("state_sha256") == hashlib.sha256(state).hexdigest() and
             policy.get("policy_sha256") == hashlib.sha256(projection).hexdigest() and
             module._no_client_grant(projection))
    for unit, socket_path, before in saved:
        raw = call_output(["/usr/bin/systemctl", "show", unit, "-p", "Id",
                           "-p", "LoadState", "-p", "ActiveState", "-p", "SubState",
                           "-p", "MainPID", "-p", "ControlPID", "-p", "ControlGroup",
                           "-p", "InvocationID", "-p", "NeedDaemonReload",
                           "-p", "NFileDescriptorStore"],
                          maximum=4096, timeout=_remaining(deadline, 5))
        facts = {}
        for line in raw.decode("ascii").splitlines():
            key, sep, value = line.partition("=")
            need(sep and key not in facts)
            facts[key] = value
        need(facts == before)
        actor_socket_owner(Path(socket_path), int(facts["MainPID"]))
    no_private_jobs_or_units(deadline)
    return "guarded" if guarded else "passive"


def wait_guardian_ready(candidate, required=None):
    """Bound the Type=simple socket publication race without relaxing proof."""
    deadline = time.monotonic() + min(10.0, PHASE_TIMEOUT)
    while True:
        try:
            return guardian_ready(candidate, required, deadline=deadline)
        except (Refused, OSError, TimeoutError):
            if time.monotonic() >= deadline:
                raise Refused()
            time.sleep(min(0.1, max(0.0, deadline - time.monotonic())))


def dedicated_process_authority(status, gid, policy):
    """The running child must have no authority outside its sealed policy."""
    need(policy in ("dedicated_none", "dedicated_bind"))
    lines = status.splitlines()
    groups = [line for line in lines if line.startswith(b"Groups:")]
    need(len(groups) == 1 and
         all(field == str(gid).encode() for field in groups[0].split()[1:]))
    allowed = 0 if policy == "dedicated_none" else 1 << 10  # CAP_NET_BIND_SERVICE
    for key in (b"CapInh:", b"CapPrm:", b"CapEff:", b"CapBnd:", b"CapAmb:"):
        values = [line.split() for line in lines if line.startswith(key)]
        need(len(values) == 1 and len(values[0]) == 2 and
             re.fullmatch(rb"[0-9a-fA-F]{16}", values[0][1]) is not None and
             int(values[0][1], 16) & ~allowed == 0)
    no_new_privs = [line.split() for line in lines if line.startswith(b"NoNewPrivs:")]
    need(no_new_privs == [[b"NoNewPrivs:", b"1"]])


def _terminal_start_tick(raw):
    """Read Linux stat field 22 from bounded bytes, including comm with ')'."""
    need(type(raw) is bytes and 0 < len(raw) <= 4096 and b")" in raw)
    fields = raw.rsplit(b")", 1)[1].split()
    need(len(fields) > 19 and fields[19].isdigit())
    value = int(fields[19])
    need(value > 0)
    return value


def active_after_terminal(stage, mode, installed):
    """Bind the new live PID 1 actor to Header-sealed Start receipts.

    This is an active-service observation.  The separate finalized-stop
    inspector is intentionally not used while the installed client runs.
    """
    stage_fd = directory(stage, 0o700)
    try:
        stage_info = os.fstat(stage_fd)
        header = strict_json(read_private(stage_fd, "header.json", 16 * 1024 * 1024))
        need(type(header) is dict and header.get("protocol") == PROTOCOL and
             header.get("phase") == "finalized" and header.get("pending") is None and
             header.get("unit_pending") is None and header.get("mode") == mode and
             header.get("capture_started") == (mode != "socks-only"))
        leaves = header.get("leaves")
        need(type(leaves) is dict)
        objects = {}
        for label, leaf in (("terminal", "receipts/activation-owner/terminal.json"),
                            ("submitted", "receipts/activation-owner/submitted.json"),
                            ("completed", "receipts/activation-owner/completed.json"),
                            ("launch", "receipts/activation-owner/launch-consumed.json"),
                            ("archive", "receipts/activation-owner/marker-archive.json")):
            raw = read_private(stage_fd, leaf, 16384)
            need(leaves.get(leaf) == hashlib.sha256(raw).hexdigest())
            objects[label] = strict_json(raw)
        terminal, submitted, completed, launch, archive = (objects[name] for name in
            ("terminal", "submitted", "completed", "launch", "archive"))
        unit = terminal.get("private_unit")
        need(type(unit) is str and re.fullmatch(r"aegis-auto@[0-9a-f]{64}\.service", unit) and
             terminal.get("schema") == 1 and terminal.get("outcome") == "finalized" and
             terminal.get("stage") == [stage_info.st_dev, stage_info.st_ino] and
             terminal.get("transaction_nonce") == header.get("transaction_nonce") and
             terminal.get("submitted_sha256") == leaves[
                 "receipts/activation-owner/submitted.json"] and
             terminal.get("completed_sha256") == leaves[
                 "receipts/activation-owner/completed.json"] and
             terminal.get("launch_consumed_sha256") == leaves[
                 "receipts/activation-owner/launch-consumed.json"] and
             terminal.get("marker_archive_sha256") == leaves[
                 "receipts/activation-owner/marker-archive.json"] and
             terminal.get("stop_submitted_sha256") is None and
             terminal.get("stop_completed_sha256") is None)
        need(submitted.get("schema") == 1 and submitted.get("kind") == "owned-start-submitted" and
             submitted.get("unit") == unit and submitted.get("job_id", 0) > 0 and
             submitted.get("job_path") == "/org/freedesktop/systemd1/job/" +
             str(submitted["job_id"]) and
             completed.get("schema") == 1 and completed.get("kind") == "owned-start-completed" and
             completed.get("unit") == unit and completed.get("job_id") == submitted["job_id"] and
             completed.get("job_path") == submitted["job_path"] and
             completed.get("submitted_sha256") == hashlib.sha256(
                 read_private(stage_fd, "receipts/activation-owner/submitted.json", 16384)
             ).hexdigest())
        for field in ("may_send_sha256", "claim_sha256", "marker_archive_sha256",
                      "launch_consumed_sha256", "launch_ticket_sha256"):
            need(type(terminal.get(field)) is str and
                 re.fullmatch(r"[0-9a-f]{64}", terminal[field]))
        need(submitted.get("may_send_sha256") == terminal["may_send_sha256"] and
             submitted.get("claim_sha256") == terminal["claim_sha256"] and
             type(submitted.get("pid1_socket")) is list and
             type(submitted.get("pid1_netns")) is list and
             all(type(n) is int and n > 0 for n in submitted["pid1_socket"] +
                 submitted["pid1_netns"]) and
             len(submitted["pid1_socket"]) == len(submitted["pid1_netns"]) == 2)
        need(archive.get("schema") == 1 and
             archive.get("may_send_sha256") == terminal["may_send_sha256"] and
             archive.get("claim_sha256") == terminal["claim_sha256"] and
             launch.get("schema") == 1 and
             launch.get("kind") == "owned-launch-consumed" and
             launch.get("completed_sha256") == terminal["completed_sha256"] and
             launch.get("ticket_sha256") == terminal["launch_ticket_sha256"] and
             launch.get("private_unit") == unit and
             launch.get("invocation_id") == completed.get("invocation_id") and
             type(launch.get("main_pid")) is int and launch["main_pid"] > 1 and
             type(launch.get("main_start_tick")) is int and
             launch["main_start_tick"] > 0)
        invocation = completed.get("invocation_id")
        need(type(invocation) is str and re.fullmatch(r"[0-9a-fA-F]{32}", invocation) and
             invocation != "0" * 32)
        boot = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
        need(submitted.get("boot_id") == boot)
        first = active_properties(unit)
        need(first["Id"] == unit and first["LoadState"] == "loaded" and
             first["ActiveState"] == "active" and first["SubState"] == "running" and
             first["ControlPID"] == "0" and first["InvocationID"] == invocation and
             first["Type"] == "notify" and first["NotifyAccess"] == "main" and
             first["StatusText"] == "Ingress workers ready" and
             first["ControlGroup"] == "/system.slice/" + unit and
             int(first["ExecMainStartTimestampMonotonic"]) > 0)
        pid = int(first["MainPID"])
        need(pid > 1 and pid == launch["main_pid"])
        pidfd = os.pidfd_open(pid, 0)
        try:
            poller = select.poll()
            poller.register(pidfd, select.POLLIN | select.POLLHUP | select.POLLERR)
            need(not poller.poll(0))
            with open(f"/proc/{pid}/status", "rb", buffering=0) as source:
                status = source.read(16385)
            need(len(status) <= 16384 and status.startswith(b"Name:"))
            uid_line = next((line for line in status.splitlines() if line.startswith(b"Uid:\t")), None)
            gid_line = next((line for line in status.splitlines() if line.startswith(b"Gid:\t")), None)
            need(uid_line is not None and gid_line is not None)
            expected_user = first["User"] or "root"
            expected_group = first["Group"] or "root"
            need(expected_user == expected_group and
                 expected_user in ("root", "aegis-svc"))
            uid, gid = ((0, 0) if expected_user == "root" else
                        runtime_account_identity(Path("/var/lib/aegis-client")))
            need(uid_line.split()[1:5] == [str(uid).encode()] * 4 and
                 gid_line.split()[1:5] == [str(gid).encode()] * 4)
            if uid != 0:
                binding = header.get("runtime_binding")
                need(type(binding) is dict)
                dedicated_process_authority(status, gid, binding.get("policy"))
            cgroup = Path(f"/proc/{pid}/cgroup").read_text()
            need(cgroup == "0::/system.slice/" + unit + "\n")
            with open(f"/proc/{pid}/stat", "rb", buffering=0) as source:
                process_stat = source.read(4097)
            need(_terminal_start_tick(process_stat) == launch["main_start_tick"])
            running = os.open(f"/proc/{pid}/exe", os.O_RDONLY | os.O_CLOEXEC)
            installed_fd = os.open(installed, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
            try:
                need(file_sha(running) == file_sha(installed_fd))
            finally:
                os.close(running)
                os.close(installed_fd)
            need(active_properties(unit) == first and not poller.poll(0))
        finally:
            os.close(pidfd)
    finally:
        os.close(stage_fd)


def install_candidate(candidate, installed, previous):
    """Publish the prepared executable atomically while its worker owns flock."""
    source = os.open(candidate, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    parent = directory(installed.parent)
    temp = ".aegis-client-auto-v2-" + os.urandom(12).hex()
    try:
        before = os.fstat(source)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and
             before.st_uid == 0 and before.st_size > 0 and
             before.st_mode & 0o111 and not before.st_mode & 0o022)
        try:
            old_fd = os.open(installed.name, os.O_RDONLY | os.O_NOFOLLOW |
                             os.O_CLOEXEC, dir_fd=parent)
        except FileNotFoundError:
            need(previous is None)
        else:
            try:
                old = os.fstat(old_fd)
                need(previous is not None and stat.S_ISREG(old.st_mode) and
                     old.st_uid == old.st_gid == 0 and old.st_nlink == 1 and
                     (old.st_dev, old.st_ino, old.st_size, stat.S_IMODE(old.st_mode)) ==
                     (previous["device"], previous["inode"], previous["size"],
                      previous["mode"]) and
                     file_sha(old_fd) == (previous["size"], previous["sha256"]))
            finally:
                os.close(old_fd)
        target = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW |
                         os.O_CLOEXEC, 0o700, dir_fd=parent)
        try:
            while True:
                chunk = os.read(source, 65536)
                if not chunk:
                    break
                view = memoryview(chunk)
                while view:
                    written = os.write(target, view)
                    need(written > 0)
                    view = view[written:]
            after = os.fstat(source)
            need((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns,
                  before.st_ctime_ns, before.st_mode, before.st_uid, before.st_gid) ==
                 (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns,
                  after.st_ctime_ns, after.st_mode, after.st_uid, after.st_gid))
            os.fchmod(target, 0o755)
            os.fsync(target)
        finally:
            os.close(target)
        os.replace(temp, installed.name, src_dir_fd=parent, dst_dir_fd=parent)
        os.fsync(parent)
    finally:
        try:
            os.unlink(temp, dir_fd=parent)
        except FileNotFoundError:
            pass
        os.close(parent)
        os.close(source)


def snapshot_old_binary(parent, installed_binary):
    directory_fd = directory(installed_binary.parent)
    try:
        try:
            source = os.open(installed_binary.name, os.O_RDONLY | os.O_NOFOLLOW |
                             os.O_CLOEXEC, dir_fd=directory_fd)
        except FileNotFoundError:
            return None
        try:
            before = os.fstat(source)
            need(stat.S_ISREG(before.st_mode) and before.st_uid == before.st_gid == 0 and
                 before.st_nlink == 1 and 0 < before.st_size <= 256 * 1024 * 1024 and
                 stat.S_IMODE(before.st_mode) in (0o555, 0o755))
            name = "backup-" + os.urandom(16).hex() + ".bin"
            backup = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                             os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=parent)
            digest = hashlib.sha256()
            size = 0
            try:
                while True:
                    chunk = os.read(source, 65536)
                    if not chunk:
                        break
                    size += len(chunk)
                    need(size <= before.st_size)
                    digest.update(chunk)
                    view = memoryview(chunk)
                    while view:
                        written = os.write(backup, view)
                        need(written > 0)
                        view = view[written:]
                os.fsync(backup)
                saved = os.fstat(backup)
                after = os.fstat(source)
                need(size == before.st_size == saved.st_size and
                     stat.S_ISREG(saved.st_mode) and saved.st_uid == saved.st_gid == 0 and
                     stat.S_IMODE(saved.st_mode) == 0o600 and saved.st_nlink == 1 and
                     (before.st_dev, before.st_ino) != (saved.st_dev, saved.st_ino) and
                     (before.st_dev, before.st_ino, before.st_mtime_ns, before.st_ctime_ns) ==
                     (after.st_dev, after.st_ino, after.st_mtime_ns, after.st_ctime_ns))
            finally:
                os.close(backup)
            os.fsync(parent)
            return {"name": name, "sha256": digest.hexdigest(), "device": before.st_dev,
                    "inode": before.st_ino, "backup_device": saved.st_dev,
                    "backup_inode": saved.st_ino, "size": size,
                    "mode": stat.S_IMODE(before.st_mode)}
        finally:
            os.close(source)
    finally:
        os.close(directory_fd)


def record_stage(stage, candidate_sha256, installed_binary, handoff=None,
                 boot_intent_sha256=None):
    parent = control_directory()
    try:
        need(current_pointer(parent) is None)
        need(not unsealed_recovery_present(parent))
        if handoff is None:
            no_prepare_handoff(parent)
        else:
            need(type(handoff) is tuple and len(handoff) == 2)
            for leaf, raw in zip((PREPARE_CURRENT, PREPARE_COMPLETED), handoff):
                need(control_leaf(parent, leaf)[0] == raw)
            intent, completed = map(strict_json, handoff)
            need(intent.get("stage") == completed.get("stage") == str(stage) and
                 intent.get("boot_id") == current_boot() and
                 completed.get("intent_sha256") == hashlib.sha256(handoff[0]).hexdigest())
            verify_handoff_candidate(handoff[1], candidate_sha256)
            need((intent.get("schema") == "aegis_auto_v2_boot_prepare_handoff_v2") ==
                 (boot_intent_sha256 is not None))
        if boot_intent_sha256 is not None:
            need(type(boot_intent_sha256) is str and
                 re.fullmatch(r"[0-9a-f]{64}", boot_intent_sha256) and
                 type(handoff) is tuple and len(handoff) == 2)
            boot_raw = boot_pending_recovery_intent(parent, {
                "boot_id":current_boot(),"candidate_sha256":candidate_sha256})
            boot = strict_json(boot_raw)
            prepare, completed = map(strict_json, handoff)
            need(hashlib.sha256(boot_raw).hexdigest() == boot_intent_sha256 and
                 prepare.get("schema") == "aegis_auto_v2_boot_prepare_handoff_v2" and
                 prepare.get("boot_intent_sha256") == boot_intent_sha256 and
                 completed.get("boot_intent_sha256") == boot_intent_sha256 and
                 prepare["stage"] == completed["stage"] == str(stage) and
                 prepare["boot_id"] == boot["new_boot_id"] and
                 prepare["public_payload_root"] == boot["public_payload_root"] and
                 prepare["candidate_binary"] == boot["candidate_binary"] and
                 completed["candidate_sha256"] == boot["candidate_sha256"] ==
                     candidate_sha256)
        previous = snapshot_old_binary(parent, installed_binary)
        pointer = {"schema": ("aegis_installer_auto_v2_boot_stage_v3"
                              if boot_intent_sha256 is not None else
                              "aegis_installer_auto_v2_stage_v2"),
                   "stage": str(stage), "status": "pending",
                   "boot_id": current_boot(),
                   "candidate_sha256": candidate_sha256,
                   "installed_binary": str(installed_binary),
                   "previous_binary": previous}
        if boot_intent_sha256 is not None:
            pointer.update({"boot_intent_sha256":boot_intent_sha256,
                            "prepare_intent_sha256":hashlib.sha256(handoff[0]).hexdigest(),
                            "prepare_completed_sha256":hashlib.sha256(handoff[1]).hexdigest()})
        payload = json.dumps(pointer, separators=(",", ":")).encode()
        need(len(payload) <= 8192)
        atomic_exclusive_bytes(parent, POINTER, payload)
        need(control_leaf(parent, POINTER, MAX_REPLY)[0] == payload)
        return previous
    finally:
        os.close(parent)



def record_prepared_stage(stage, paths, args, progress):
    """Consume Prepare custody under the original lock, before worker launch."""
    install_fd = _open_original_lock("/run/aegis-auto-install.lock", 9)
    try:
        progress["phase"] = "prepare_handoff"
        handoff = admitted_prepare_handoff(stage, paths)
        progress["phase"] = "reference_custody"
        passive_prepared_reference_match(stage, paths, args)
        candidate = os.open(paths["candidate-binary"], os.O_RDONLY |
                            os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            candidate_sha = file_sha(candidate)[1]
        finally:
            os.close(candidate)
        verify_handoff_candidate(handoff[1], candidate_sha)
        fresh_package_lock(install_fd)
        progress["phase"] = "stage_pointer"
        previous = record_stage(stage, candidate_sha, paths["installed-binary"], handoff,
                                getattr(args, "_boot_intent_sha256", None))
        fresh_package_lock(install_fd)
        progress["phase"] = "prepare_handoff_archive"
        archive_prepare_handoff(handoff)
        fresh_package_lock(install_fd)
        return previous
    finally:
        os.close(install_fd)



def record_failure(progress, error):
    """Best-effort, fixed private diagnostics; never changes transaction result."""
    phase = progress.get("phase")
    need(phase in FAILURE_PHASES)
    worker = progress.get("worker")
    status = worker.poll() if worker is not None else None
    need(status is None or type(status) is int and -255 <= status <= 255)
    started = progress.get("worker_started")
    remaining = None if started is None else max(
        0, min(900000, int((started + WORKER_TIMEOUT - time.monotonic()) * 1000)))
    reason = ("refused" if isinstance(error, Refused) else
              "timeout" if isinstance(error, (TimeoutError, subprocess.TimeoutExpired)) else
              "os_error" if isinstance(error, OSError) else "unexpected")
    value = {"schema": "aegis_installer_auto_v2_failure_v1",
             "phase": phase, "reason": reason,
             "worker_exit": status, "remaining_ms": remaining}
    diagnostic = getattr(error, "worker_diagnostic", None)
    if diagnostic is not None:
        need(isinstance(error, Refused) and phase == "begin_capture")
        value["worker_diagnostic"] = start_failure_diagnostic(diagnostic)
    capture_refusal = getattr(error, "capture_refusal", None)
    if capture_refusal is not None:
        need(isinstance(error, Refused) and phase == "begin_capture" and
             diagnostic is None)
        value["capture_refusal"] = capture_refusal_diagnostic(capture_refusal)
    step = getattr(error, "begin_capture_step", None)
    if step is not None:
        need(isinstance(error, Refused) and phase == "begin_capture")
        value["begin_capture_step"] = begin_capture_step(step)
    bind_step = getattr(error, "bind_runtime_step", None)
    if bind_step is not None:
        need(isinstance(error, Refused) and
             (phase == "bind_runtime" or
              (phase == "begin_capture" and bind_step in
               ("worker_pin_before", "worker_pin_after"))))
        value["bind_runtime_step"] = bind_runtime_step(bind_step)
    reload_failure = getattr(error, 'reload_failure', None)
    if reload_failure is not None:
        need(isinstance(error, Refused) and phase == 'reload_policy' and
             reload_failure in RELOAD_FAILURES)
        value['reload_failure'] = reload_failure
    payload = json.dumps(value, separators=(",", ":")).encode()
    need(len(payload) <= 512)
    parent = control_directory()
    try:
        fd = os.open("failure-" + os.urandom(16).hex() + ".json",
                     os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW |
                     os.O_CLOEXEC, 0o600, dir_fd=parent)
        try:
            need(os.write(fd, payload) == len(payload))
            os.fsync(fd)
        finally:
            os.close(fd)
        os.fsync(parent)
    finally:
        os.close(parent)


def inspect_after_stop(installed, stage, boot_id):
    raw = call_output([installed, "auto-seal-stopped-generation", stage],
                      maximum=128 * 1024, timeout=30, diagnostic_stderr=True)
    record = strict_json(raw)
    need(type(record) is dict and record.get("schema") ==
         "aegis_auto_v2_stopped_stage_inspection_v1" and
         record.get("stage", {}).get("path") == stage and
         record.get("published_paths", {}).get("current_verified") is True)
    terminal = record.get("terminal")
    need(type(terminal) is dict and terminal.get("outcome") == "finalized-stopped" and
         terminal.get("boot_id") == boot_id and
         type(terminal.get("stop_terminal_sha256")) is str and
         re.fullmatch(r"[0-9a-f]{64}", terminal["stop_terminal_sha256"]))
    need(record.get("main", {}).get("stopped_verified") is True and
         record.get("main", {}).get("no_live_lease_verified") is True and
         record.get("main", {}).get("fdstore_empty_verified") is True and
         record.get("guardian", {}).get("deny_verified") is True and
         record.get("guardian", {}).get("fdstore_empty_verified") is True)
    # The typed inspector accepts either verified inactive or PID1-collected
    # state. A collected unit's systemctl query exits nonzero; its collection
    # timing is not part of the durable generation identity.
    return record


def inspect_unsealed_after_stop(installed, stage, boot_id):
    """Authenticate stopped recovery without minting an active generation."""
    raw = call_output([installed, "auto-seal-unsealed-stopped-recovery", stage],
                      maximum=128 * 1024, timeout=30)
    record = strict_json(raw)
    need(type(record) is dict and record.get("schema") ==
         "aegis_auto_v2_stopped_stage_inspection_v1" and
         record.get("stage", {}).get("path") == stage and
         record.get("published_paths", {}).get("current_verified") is True)
    terminal = record.get("terminal")
    need(type(terminal) is dict and terminal.get("outcome") == "finalized-stopped" and
         terminal.get("boot_id") == boot_id and
         type(terminal.get("stop_terminal_sha256")) is str and
         re.fullmatch(r"[0-9a-f]{64}", terminal["stop_terminal_sha256"]))
    need(record.get("main", {}).get("stopped_verified") is True and
         record.get("main", {}).get("no_live_lease_verified") is True and
         record.get("main", {}).get("fdstore_empty_verified") is True and
         record.get("guardian", {}).get("deny_verified") is True and
         record.get("guardian", {}).get("fdstore_empty_verified") is True and
         record["guardian"].get("prior_manager_binding_sha256") is None)
    return record


def unsealed_recovery_present(parent):
    try:
        control_leaf(parent, "generation-recovery-stopped.json", maximum=136 * 1024)
    except FileNotFoundError:
        return False
    return True


def verified_stop(pointer, required_mode=None):
    installed = pointer["installed_binary"]
    stage = pointer["stage"]
    binary = os.open(installed, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info = os.fstat(binary)
        need(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1 and
             info.st_mode & 0o111 and file_sha(binary)[1] == pointer["candidate_sha256"])
    finally:
        os.close(binary)
    need(pointer["boot_id"] == current_boot())
    # A prior stop may have completed before its caller archived the pointer.
    # Only the production inspector can establish that state.
    try:
        return "stopped", inspect_after_stop(installed, stage, pointer["boot_id"])
    except (Refused, OSError, ValueError, UnicodeError, json.JSONDecodeError,
            subprocess.SubprocessError):
        pass
    try:
        return "recovery_required", inspect_unsealed_after_stop(
            installed, stage, pointer["boot_id"])
    except (Refused, OSError, ValueError, UnicodeError, json.JSONDecodeError,
            subprocess.SubprocessError):
        pass
    stop_verb = "auto-stop-finalized-socks" if required_mode == "socks-only" else "auto-stop-finalized"
    need(call_output([installed, stop_verb, stage], maximum=4096,
                     timeout=45, diagnostic_stderr=True) == b"")
    try:
        return "stopped", inspect_after_stop(installed, stage, pointer["boot_id"])
    except (Refused, OSError, ValueError, UnicodeError, json.JSONDecodeError,
            subprocess.SubprocessError):
        return "recovery_required", inspect_unsealed_after_stop(
            installed, stage, pointer["boot_id"])


def stop_current(required_mode=None):
    need(sys.platform == "linux" and os.geteuid() == 0)
    parent = control_directory()
    try:
        current = current_pointer(parent)
        if current is None:
            return "recovery_required" if unsealed_recovery_present(parent) else "noop"
        pointer, raw, identity = current
        stop_status, stopped_report = verified_stop(pointer, required_mode)
        if required_mode == "socks-only":
            need(stopped_report.get("stage", {}).get("mode") == "socks-only")
        if stop_status == "recovery_required":
            # A genuine Stop occurred, but no active-generation seal exists.
            # Keep the candidate and pending pointer for the separate recovery
            # command; archiving it here would disguise this generation.
            again = current_pointer(parent)
            need(again is not None and again[1] == raw and
                 (again[2].st_dev, again[2].st_ino) == (identity.st_dev, identity.st_ino))
            return "recovery_required"
        need(stop_status == "stopped")
        # The installed Rust command re-admits the sealed Stop and retires the
        # exact pointer under the original InstallLock. A Python readback and
        # unlink here could race a new Prepare into deleting its pointer.
        need(call_output([pointer["installed_binary"],
                          "auto-archive-stopped-generation", pointer["stage"]],
                         maximum=1024, timeout=120) == b"")
        return "stopped"
    finally:
        os.close(parent)


UNINSTALL_OWNERS = (
    "/var/lib/aegis-auto/control",
    "/var/lib/aegis-install/client/auto-guardian-install.json",
    "/var/lib/aegis-install/client/auto-guard-first-arm.json",
    "/var/lib/aegis-install/client/device-guard.conf",
    "/var/lib/aegis-auto/fresh-passive-abort-current.json",
    "/etc/systemd/system/aegis-auto-guardian.service",
    "/etc/systemd/system/aegis-auto-guardian-watchdog.service",
    "/etc/systemd/system/aegis-auto-capture-topology.service",
    "/etc/systemd/system/aegis-auto-trace-rollback-actor.service",
    "/etc/systemd/system/aegis-device-egress-guard.service",
    "/etc/systemd/system/aegis-foreign-policy-monitor.service",
    "/etc/systemd/system/aegis-auto-clean-shutdown.service",
    "/etc/systemd/system/aegis-device-dhcp-refresh.service",
    "/etc/systemd/system/aegis-device-dhcp-refresh.timer",
    # Registrar-owned active terminal authority is separate from the passive
    # package. Archive its exact bytes before generic package removal.
    "/etc/aegis-auto-terminal-source.json",
    "/etc/aegis-auto-terminal-store.json",
    "/usr/lib/systemd/system-shutdown/aegis-auto-terminal-hook",
    "/etc/systemd/system/NetworkManager.service.d/31-aegis-auto-terminal-transition.conf",
    "/etc/systemd/system/systemd-networkd.service.d/31-aegis-auto-terminal-transition.conf",
    "/etc/systemd/system/networking.service.d/31-aegis-auto-terminal-transition.conf",
    "/etc/systemd/system/aegis-auto-guardian.service.d/31-aegis-auto-terminal-transition.conf",
)


def _uninstall_owner_is_unit(path):
    return path.startswith("/etc/systemd/system/") and path.endswith(".service")


def _uninstall_terminal_history(installed):
    path = '/usr/local/lib/aegis/helpers/lib/aegis_auto_boot_transition.py'
    raw = bounded_root_bytes(path, 1 << 20, (0o500,))
    need(type(installed.get('terminal_transition_sha256')) is str and
         hashlib.sha256(raw).hexdigest() ==
         installed['terminal_transition_sha256'])
    namespace = {'__file__': path, '__name__': 'aegis_uninstall_terminal_history'}
    exec(compile(raw, path, 'exec', dont_inherit=True), namespace)
    return types.SimpleNamespace(**namespace)


def _uninstall_terminal_migration_roster(history, source, store):
    directory = Path('/var/lib/aegis-install/client/terminal-migrations')
    if not directory.exists() and not directory.is_symlink():
        return
    need(source is not None and store is not None and
         not directory.is_symlink())
    info = os.lstat(directory)
    need(stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == 0 and
         stat.S_IMODE(info.st_mode) == 0o700)
    names = set(os.listdir(directory))
    need(len(names) <= 512 and 'pending.json' not in names and
         'head.json' in names)
    head_raw = bounded_root_bytes(directory / 'head.json', 4096, (0o600,))
    head = strict_json(head_raw)
    need(type(head) is dict and set(head) == {'schema', 'edge_sha256'} and
         head['schema'] == 'aegis_auto_terminal_migration_head_v1' and
         re.fullmatch(r'[0-9a-f]{64}', head['edge_sha256']))
    expected = {'head.json'}
    cursor = head['edge_sha256']
    visited = set()
    for _ in range(32):
        need(cursor not in visited)
        visited.add(cursor)
        edge_name = 'edge-' + cursor + '.json'
        complete_name = 'complete-' + cursor + '.json'
        edge_raw = bounded_root_bytes(directory / edge_name, 8192, (0o600,))
        edge = strict_json(edge_raw)
        need(type(edge) is dict and
             hashlib.sha256(edge_raw).hexdigest() == cursor and
             type(edge.get('old_source_sha256')) is str and
             re.fullmatch(r'[0-9a-f]{64}', edge['old_source_sha256']) and
             type(edge.get('old_context_sha256')) is str and
             re.fullmatch(r'[0-9a-f]{64}', edge['old_context_sha256']))
        history.historical_source_context(edge['old_source_sha256'],
                                          source, store, None,
                                          force_history=True)
        context_name = 'context-' + edge['old_context_sha256'] + '.json'
        observer_name = 'observer-runtime-' + edge['intent_sha256'] + '.json'
        observer_raw = bounded_root_bytes(directory / observer_name,16384,(0o600,))
        need(hashlib.sha256(observer_raw).hexdigest() ==
             edge['observer_runtime_sha256'])
        orphans=edge['new_observer_orphan_sha256s']
        need(type(orphans) is list and len(orphans)<=8 and
             orphans==sorted(set(orphans)) and
             all(type(item) is str and re.fullmatch(r'[0-9a-f]{64}',item)
                 for item in orphans))
        for orphan_sha in orphans:
            orphan_name='observer-new-orphan-'+edge['intent_sha256']+'-'+orphan_sha+'.json'
            orphan_raw=bounded_root_bytes(directory/orphan_name,16384,(0o600,))
            need(hashlib.sha256(orphan_raw).hexdigest()==orphan_sha)
            expected.add(orphan_name)
        expected.update((edge_name, complete_name, context_name, observer_name))
        cursor = edge.get('prior_head_sha256')
        if cursor is None:
            break
        need(type(cursor) is str and re.fullmatch(r'[0-9a-f]{64}', cursor))
    else:
        need(False)
    need(names == expected)


def _uninstall_terminal_authority_admit():
    """Bind a complete or interrupted registrar prefix before owner backup."""
    intent_path = Path("/var/lib/aegis-install/client/auto-terminal-configure-intent.json")
    configured_path = Path("/var/lib/aegis-install/client/auto-terminal-configured.json")
    config_path = Path("/etc/aegis-auto-terminal-source.json")
    store_path = Path("/etc/aegis-auto-terminal-store.json")
    hook_path = Path("/usr/lib/systemd/system-shutdown/aegis-auto-terminal-hook")
    staged_path = Path("/usr/local/lib/aegis/helpers/lib/aegis-auto-terminal-hook")
    managers = ("NetworkManager.service", "systemd-networkd.service")
    leaf = "31-aegis-auto-terminal-transition.conf"
    manager_paths = {manager: Path("/etc/systemd/system") / (manager + ".d") / leaf
                     for manager in managers}
    guardian_path = Path("/etc/systemd/system/aegis-auto-guardian.service.d") / leaf
    legacy_path = Path("/etc/systemd/system/networking.service.d") / leaf
    active = (hook_path, store_path, config_path, *manager_paths.values(), guardian_path)
    boot_dir = Path(uninstall_journal.BOOT_STORE_ROOT)
    if not intent_path.exists() and not intent_path.is_symlink():
        migration_dir = Path('/var/lib/aegis-install/client/terminal-migrations')
        need(not migration_dir.exists() and not migration_dir.is_symlink())
        need(not configured_path.exists() and not configured_path.is_symlink())
        need(all(not path.exists() and not path.is_symlink()
                 for path in (*active, legacy_path)))
        need(not boot_dir.exists() and not boot_dir.is_symlink())
        _uninstall_terminal_registration_roster(None)
        return
    raw = bounded_root_bytes(intent_path, 4096, (0o600,))
    intent = strict_json(raw)
    keys = {'schema', 'install_sha256', 'source_sha256', 'store_sha256',
            'hook_sha256', 'selected_manager', 'dropin_sha256'}
    need(type(intent) is dict and set(intent) == keys and
         intent['schema'] == 'aegis_auto_terminal_configure_intent_v1' and
         intent['selected_manager'] in managers and
         all(type(intent[k]) is str and re.fullmatch(r'[0-9a-f]{64}', intent[k])
             for k in keys - {'schema', 'selected_manager'}))
    installed_raw = bounded_root_bytes(
        '/var/lib/aegis-install/client/auto-guardian-install.json', 1 << 20, (0o600,))
    installed = strict_json(installed_raw)
    need(hashlib.sha256(installed_raw).hexdigest() == intent['install_sha256'] and
         type(installed) is dict and
         installed.get('schema') == 'aegis_auto_guardian_install_v1' and
         installed.get('terminal_hook_staged_sha256') == intent['hook_sha256'])
    pinned = {
        'terminal_register_sha256': (
            '/usr/local/lib/aegis/helpers/lib/aegis_auto_terminal_register.py', 0o500),
        'terminal_witness_sha256': (
            '/usr/local/lib/aegis/helpers/lib/aegis_auto_terminal_witness.py', 0o500),
        'terminal_boot_store_sha256': (
            '/usr/local/lib/aegis/helpers/lib/aegis_auto_terminal_boot_store.py', 0o500),
        'terminal_transition_sha256': (
            '/usr/local/lib/aegis/helpers/lib/aegis_auto_boot_transition.py', 0o500),
        'terminal_a_unit_sha256': (
            '/etc/systemd/system/aegis-auto-terminal-a@.service', 0o644),
        'terminal_b_unit_sha256': (
            '/etc/systemd/system/aegis-auto-terminal-b@.service', 0o644),
        'terminal_observer_unit_sha256': (
            '/etc/systemd/system/aegis-auto-terminal-observer.service', 0o644),
        'terminal_transition_unit_sha256': (
            '/etc/systemd/system/aegis-auto-terminal-transition.service', 0o644),
    }
    for key, (source_path, mode) in pinned.items():
        need(type(installed.get(key)) is str and
             re.fullmatch(r'[0-9a-f]{64}', installed[key]) and
             hashlib.sha256(bounded_root_bytes(source_path, 1 << 20, (mode,))).hexdigest()
             == installed[key])
    staged = bounded_root_bytes(staged_path, 32768, (0o500,))
    need(hashlib.sha256(staged).hexdigest() == intent['hook_sha256'])
    transition = (b'[Unit]\nRequires=aegis-auto-terminal-transition.service\n'
                  b'After=aegis-auto-terminal-transition.service\n')
    need(hashlib.sha256(transition).hexdigest() == intent['dropin_sha256'])
    selected_path = manager_paths[intent['selected_manager']]
    need(all(not path.exists() and not path.is_symlink()
             for manager, path in manager_paths.items()
             if manager != intent['selected_manager']))
    need(not legacy_path.exists() and not legacy_path.is_symlink())
    sequence = ((hook_path, 0o755, intent['hook_sha256']),
                (store_path, 0o600, intent['store_sha256']),
                (config_path, 0o600, intent['source_sha256']),
                (selected_path, 0o644, intent['dropin_sha256']),
                (guardian_path, 0o644, intent['dropin_sha256']))
    missing = False
    for path, mode, expected_sha in sequence:
        exists = path.exists() or path.is_symlink()
        if not exists:
            missing = True
            continue
        need(not missing)
        data = bounded_root_bytes(path, 32768, (mode,))
        need(hashlib.sha256(data).hexdigest() == expected_sha)
        if path in (selected_path, guardian_path):
            need(data == transition)
        elif path == hook_path:
            need(data == staged)
    source = None
    store = None
    if config_path.exists() or config_path.is_symlink():
        source = strict_json(bounded_root_bytes(config_path, 4096, (0o600,)))
        need(type(source) is dict and
             source.get('schema') == 'aegis_auto_terminal_source_v1' and
             source.get('selected_manager') == intent['selected_manager'] and
             source.get('terminal_hook_staged_sha256', source.get('hook_sha256')) ==
             intent['hook_sha256'] and
             source.get('manager_transition_dropin_sha256') == intent['dropin_sha256'] and
             source.get('guardian_transition_dropin_sha256') == intent['dropin_sha256'] and
             source.get('register_sha256') == installed['terminal_register_sha256'] and
             source.get('witness_sha256') == installed['terminal_witness_sha256'] and
             source.get('boot_helper_sha256') == installed['terminal_boot_store_sha256'] and
             source.get('transition_unit_sha256') == installed['terminal_transition_unit_sha256'] and
             source.get('a_unit_sha256') == installed['terminal_a_unit_sha256'] and
             source.get('b_unit_sha256') == installed['terminal_b_unit_sha256'] and
             source.get('observer_unit_sha256') == installed['terminal_observer_unit_sha256'])
    if store_path.exists() or store_path.is_symlink():
        store = strict_json(bounded_root_bytes(store_path, 4096, (0o600,)))
        need(type(store) is dict and
             store.get('schema') == 'aegis_auto_terminal_boot_store_v1' and
             store.get('hook_sha256') == intent['hook_sha256'])
    history = _uninstall_terminal_history(installed)
    if boot_dir.exists() or boot_dir.is_symlink():
        boot = os.lstat('/boot')
        entry = os.lstat(boot_dir)
        need(stat.S_ISDIR(boot.st_mode) and stat.S_ISDIR(entry.st_mode) and
             boot.st_uid == boot.st_gid == entry.st_uid == entry.st_gid == 0 and
             stat.S_IMODE(entry.st_mode) == 0o700 and
             boot.st_dev == entry.st_dev != os.stat('/').st_dev)
        if store_path.exists() or store_path.is_symlink():
            need(store.get('boot_store_dir') == boot_dir.name and
                 store.get('boot_dev') ==
                 f'{os.major(entry.st_dev)}:{os.minor(entry.st_dev)}')
        names = sorted(os.listdir(boot_dir))
        need(len(names) <= 128)
        marker_keys = {'schema', 'old_boot_id', 'boot_uuid', 'source_sha256',
                       'intent_sha256', 'nonce', 'a_sha256', 'clean_stop_sha256',
                       'b_sha256', 'policy_sha256', 'active_generation_sha256',
                       'active_report_sha256', 'boot_snapshot_sha256', 'final_job',
                       'final_job_type', 'action', 'pid1_tick', 'root_uuid',
                       'root_dev', 'boot_dev', 'hook_sha256', 'helper_sha256'}
        for name in names:
            need(re.fullmatch(r'terminal-[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}-[0-9a-f]{32}\.json', name))
            raw_marker = bounded_root_bytes(boot_dir / name, 4096, (0o600,))
            marker = strict_json(raw_marker)
            need(raw_marker == uninstall_journal.canonical(marker) and
                 type(marker) is dict and set(marker) == marker_keys and
                 marker['schema'] == 'aegis_auto_terminal_boot_v1' and
                 name == 'terminal-' + marker['old_boot_id'] + '-' + marker['nonce'] + '.json' and
                 marker['action'] in ('reboot', 'poweroff') and
                 marker['final_job_type'] == 'start' and
                 type(marker['final_job']) is int and 0 < marker['final_job'] < 1 << 32 and
                 type(marker['pid1_tick']) is int and 0 <= marker['pid1_tick'] < 1 << 64 and
                 all(type(marker[key]) is str and re.fullmatch(r'[0-9a-f]{64}', marker[key])
                     for key in ('source_sha256', 'intent_sha256', 'a_sha256',
                                 'clean_stop_sha256', 'b_sha256', 'policy_sha256',
                                 'active_generation_sha256', 'active_report_sha256',
                                 'boot_snapshot_sha256', 'hook_sha256', 'helper_sha256')))
            need(store_path.exists() and config_path.exists())
            old_source, old_store = history.historical_source_context(
                marker['source_sha256'], source, store,
                hashlib.sha256(raw_marker).hexdigest())
            need(old_source['hook_sha256'] == old_store['hook_sha256'] and
                 marker['boot_uuid'] == old_store['boot_uuid'] and
                 marker['boot_dev'] == old_store['boot_dev'] == store['boot_dev'] and
                 marker['root_uuid'] == old_store['root_uuid'] and
                 marker['root_dev'] == old_store['root_dev'] == store['root_dev'] and
                 marker['hook_sha256'] == old_store['hook_sha256'] and
                 marker['helper_sha256'] == old_store['helper_sha256'])
    elif configured_path.exists() or configured_path.is_symlink():
        need(False)
    if configured_path.exists() or configured_path.is_symlink():
        configured = strict_json(bounded_root_bytes(configured_path, 4096, (0o600,)))
        need(configured == {'schema': 'aegis_auto_terminal_configured_v1',
                            **{key: intent[key] for key in keys - {'schema'}}} and
             not missing)
    if source is not None and store is not None:
        history.historical_carriers_closed(store, source)
    _uninstall_terminal_migration_roster(history, source, store)
    _uninstall_terminal_registration_roster(intent['source_sha256'],
                                             history, source, store)


def _uninstall_terminal_registration_source(value, current_sha, history,
                                            current_source, current_store):
    if type(value) is not str or not re.fullmatch(r'[0-9a-f]{64}', value):
        return False
    if value == current_sha:
        return True
    need(history is not None and current_source is not None and
         current_store is not None)
    old_source, old_store = history.historical_source_context(
        value, current_source, current_store, None)
    need(old_source.get('schema') == 'aegis_auto_terminal_source_v1' and
         old_store.get('schema') == 'aegis_auto_terminal_boot_store_v1' and
         old_store['root_uuid'] == current_store['root_uuid'] and
         old_store['boot_uuid'] == current_store['boot_uuid'])
    return True


def _uninstall_terminal_registration_roster(source_sha, history=None,
                                            source=None, store=None):
    """Admit exact durable registrar receipts before copying client state."""
    root = Path('/var/lib/aegis-install/client')
    names = sorted(path.name for path in root.iterdir())
    need(len(names) <= 512)
    rows = {}
    for name in names:
        if (not name.startswith('auto-terminal-registration-') and
            not name.startswith('auto-terminal-activation-')):
            continue
        if name.startswith('auto-terminal-activation-'):
            match = re.fullmatch(
                r'auto-terminal-activation-(preseal-)?([0-9a-f]{64})\.json',
                name)
            need(match is not None)
            kind, token = ('preseal' if match[1] else 'activation'), match[2]
        else:
            match = re.fullmatch(r'auto-terminal-registration-(pending|complete|compensated)-([0-9a-f]{64})\.json', name)
            need(match is not None)
            kind, token = match.groups()
        need(match is not None and source_sha is not None)
        raw = bounded_root_bytes(root / name, 4096, (0o600,))
        value = strict_json(raw)
        need(raw == uninstall_journal.canonical(value) + b'\n' and
             type(value) is dict and
             (token, kind) not in rows)
        if kind == 'pending':
            need(set(value) == {'schema', 'boot_id', 'unit', 'source_sha256'} and
                 value['schema'] == 'aegis_auto_terminal_registration_pending_v1' and
                 value['unit'] == f'aegis-auto@{token}.service' and
                 re.fullmatch(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}', value['boot_id']) and
                 _uninstall_terminal_registration_source(
                     value['source_sha256'], source_sha, history, source, store))
        elif kind == 'complete':
            need(set(value) == {'schema', 'pending_sha256', 'activation_sha256',
                                'active_generation_sha256'} and
                 value['schema'] == 'aegis_auto_terminal_registration_complete_v1' and
                 all(type(value[key]) is str and re.fullmatch(r'[0-9a-f]{64}', value[key])
                     for key in ('pending_sha256', 'activation_sha256',
                                 'active_generation_sha256')))
        elif kind == 'compensated':
            need(set(value) == {'schema', 'pending_sha256', 'unit', 'source_sha256'} and
                 value['schema'] == 'aegis_auto_terminal_registration_compensated_v1' and
                 value['unit'] == f'aegis-auto@{token}.service' and
                 _uninstall_terminal_registration_source(
                     value['source_sha256'], source_sha, history, source, store) and
                 type(value['pending_sha256']) is str and
                 re.fullmatch(r'[0-9a-f]{64}', value['pending_sha256']))
        elif kind == 'preseal':
            need(set(value)=={'schema','boot_id','unit','nonce','stage_path',
                              'stage_dev','stage_ino','terminal_sha256',
                              'installed_generation_sha256',
                              'installed_manifest_sha256','source_sha256'} and
                 value['schema']=='aegis_auto_terminal_activation_preseal_v1' and
                 value['unit']==f'aegis-auto@{token}.service' and
                 re.fullmatch(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}',
                              value['boot_id']) and
                 type(value['nonce']) is str and
                 re.fullmatch(r'[0-9a-f]{32}',value['nonce']) and
                 type(value['stage_path']) is str and
                 value['stage_path'].startswith('/run/aegis-') and
                 type(value['stage_dev']) is int and value['stage_dev']>=0 and
                 type(value['stage_ino']) is int and value['stage_ino']>0 and
                 _uninstall_terminal_registration_source(
                     value['source_sha256'],source_sha,history,source,store) and
                 all(type(value[key]) is str and
                     re.fullmatch(r'[0-9a-f]{64}',value[key]) for key in
                     ('terminal_sha256','installed_generation_sha256',
                      'installed_manifest_sha256')))
        else:
            need(set(value)=={'schema','boot_id','unit','nonce','stage_path',
                              'stage_dev','stage_ino','terminal_sha256',
                              'installed_generation_sha256',
                              'installed_manifest_sha256',
                              'active_generation_sha256',
                              'active_report_sha256','boot_snapshot_sha256',
                              'source_sha256'} and
                 value['schema']=='aegis_auto_terminal_activation_v1' and
                 value['unit']==f'aegis-auto@{token}.service' and
                 re.fullmatch(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}',
                              value['boot_id']) and
                 type(value['nonce']) is str and
                 re.fullmatch(r'[0-9a-f]{32}',value['nonce']) and
                 type(value['stage_path']) is str and
                 value['stage_path'].startswith('/run/aegis-') and
                 type(value['stage_dev']) is int and value['stage_dev']>=0 and
                 type(value['stage_ino']) is int and value['stage_ino']>0 and
                 _uninstall_terminal_registration_source(
                     value['source_sha256'],source_sha,history,source,store) and
                 all(type(value[key]) is str and
                     re.fullmatch(r'[0-9a-f]{64}',value[key]) for key in
                     ('terminal_sha256','installed_generation_sha256',
                      'installed_manifest_sha256',
                      'active_generation_sha256','active_report_sha256',
                      'boot_snapshot_sha256')))
        rows[token, kind] = (value, hashlib.sha256(raw).hexdigest())
    for token in {key[0] for key in rows}:
        pending = rows.get((token, 'pending'))
        complete = rows.get((token, 'complete'))
        compensated = rows.get((token, 'compensated'))
        activation = rows.get((token, 'activation'))
        preseal = rows.get((token, 'preseal'))
        need(pending is not None or compensated is not None)
        if preseal is not None:
            need(preseal[0]['source_sha256']==
                 (pending[0]['source_sha256'] if pending is not None
                  else compensated[0]['source_sha256']) and
                 preseal[0]['unit']==f'aegis-auto@{token}.service')
        if activation is not None:
            need(activation[0]['source_sha256']==
                 (pending[0]['source_sha256'] if pending is not None
                  else compensated[0]['source_sha256']))
            if preseal is not None:
                need(all(activation[0][key]==preseal[0][key] for key in
                         ('boot_id','unit','nonce','stage_path','stage_dev',
                          'stage_ino','terminal_sha256',
                          'installed_generation_sha256',
                          'installed_manifest_sha256','source_sha256')))
        if compensated is not None and pending is not None:
            need(compensated[0]['pending_sha256'] == pending[1])
        if complete is not None:
            need(complete[0]['pending_sha256'] ==
                 (pending[1] if pending is not None else compensated[0]['pending_sha256']))
            if activation is not None:
                need(complete[0]['activation_sha256']==activation[1] and
                     complete[0]['active_generation_sha256']==
                         activation[0]['active_generation_sha256'])
            else:
                need((pending[0]['source_sha256'] if pending is not None
                      else compensated[0]['source_sha256'])!=source_sha)


def _uninstall_owner_fact(name):
    """Read exact fixed-path identity without following any path component."""
    path = absolute(name)
    parent = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW |
                     os.O_CLOEXEC)
    try:
        for component in path.parts[1:-1]:
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY |
                            os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
            info = os.fstat(child)
            need(stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == 0 and
                 not stat.S_IMODE(info.st_mode) & 0o022)
            os.close(parent)
            parent = child
        try:
            info = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError:
            return {"path": name, "kind": "absent"}
        need(info.st_uid == info.st_gid == 0 and info.st_nlink >= 1 and
             not stat.S_ISLNK(info.st_mode))
        if stat.S_ISDIR(info.st_mode):
            child = os.open(path.name, os.O_RDONLY | os.O_DIRECTORY |
                            os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
            try:
                same = os.fstat(child)
                need((same.st_dev, same.st_ino) == (info.st_dev, info.st_ino) and
                     not stat.S_IMODE(same.st_mode) & 0o022)
                names = sorted(os.listdir(child))
                need(len(names) <= 4096 and all("/" not in part for part in names))
                content = hashlib.sha256(uninstall_journal.canonical(names)).hexdigest()
            finally:
                os.close(child)
            kind = "directory"
        else:
            need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and
                 info.st_size <= 256 << 20)
            child = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW |
                            os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=parent)
            try:
                same = os.fstat(child)
                need((same.st_dev, same.st_ino) == (info.st_dev, info.st_ino))
                content = file_sha(child)[1]
            finally:
                os.close(child)
            kind = "file"
        return {"path": name, "kind": kind, "device": info.st_dev,
                "inode": info.st_ino, "mode": stat.S_IMODE(info.st_mode),
                "size": info.st_size, "content_sha256": content}
    finally:
        os.close(parent)


def _uninstall_source_facts(*, expected_boot=None):
    control = control_directory()
    try:
        current = current_pointer(control)
        need(current is not None and not unsealed_recovery_present(control))
        pointer, raw, _identity = current
        need(pointer["boot_id"] == (current_boot() if expected_boot is None
                                   else expected_boot))
    finally:
        os.close(control)
    binary = held_root_file(Path(pointer["installed_binary"]), 256 << 20,
                            (0o555, 0o755))
    try:
        need(file_sha(binary)[1] == pointer["candidate_sha256"])
    finally:
        os.close(binary)
    owners = [_uninstall_owner_fact(path) for path in UNINSTALL_OWNERS]
    need(owners[0]["kind"] == "directory")
    version = call_output(["/usr/bin/dpkg-query", "--show",
                           "--showformat=${Status}\n${Version}\n", "aegis-client"],
                          maximum=256, timeout=10).decode("ascii", "strict").splitlines()
    need(len(version) == 2 and version[0] == "install ok installed")
    guard = next(item for item in owners if item["path"] ==
                 "/var/lib/aegis-install/client/device-guard.conf")
    return pointer, raw, owners, version[1], guard


def begin_uninstall():
    """Admit one installed generation under its original InstallLock."""
    need(sys.platform == "linux" and os.geteuid() == 0)
    lock_fd = _open_original_lock("/run/aegis-auto-install.lock", 9,
                                  allow_uninstall=True, create=True)
    try:
        journal_fd = uninstall_journal.directory(create=True)
        try:
            if not uninstall_journal.absent(journal_fd, "intent.json"):
                prior, phases = uninstall_journal.read(journal_fd)
                need(prior["package"] == "aegis-client")
                if not phases:
                    pointer, raw, owners, version, guard = _uninstall_source_facts()
                    need(prior["boot_id"] == pointer["boot_id"] and
                         prior["stage"] == pointer["stage"] and
                         prior["pointer_sha256"] == hashlib.sha256(raw).hexdigest() and
                         prior["candidate_sha256"] == pointer["candidate_sha256"] and
                         prior["owner_manifest_sha256"] == hashlib.sha256(
                             uninstall_journal.canonical(owners)).hexdigest() and
                         prior["guard_config_sha256"] == guard.get("content_sha256",
                             hashlib.sha256(b"absent").hexdigest()) and
                         prior["version"] == version)
                    observation = hashlib.sha256(
                        raw + uninstall_journal.canonical(owners)).hexdigest()
                    _prior, phases = uninstall_journal.advance(
                        journal_fd, "admitted", observation)
                return {"state": phases[-1][0]["state"], "stage": prior["stage"]}
            pointer, raw, owners, version, guard = _uninstall_source_facts()
            intent = {"schema": uninstall_journal.SCHEMA,
                      "boot_id": pointer["boot_id"], "stage": pointer["stage"],
                      "pointer_sha256": hashlib.sha256(raw).hexdigest(),
                      "candidate_sha256": pointer["candidate_sha256"],
                      "owner_manifest_sha256": hashlib.sha256(
                          uninstall_journal.canonical(owners)).hexdigest(),
                      "guard_config_sha256": guard.get("content_sha256",
                          hashlib.sha256(b"absent").hexdigest()),
                      "package": "aegis-client", "version": version,
                      "backup_root": "/var/lib/aegis-auto-uninstall/backup",
                      "nonce": secrets.token_hex(16)}
            uninstall_journal.begin(journal_fd, intent)
            observation = hashlib.sha256(raw + uninstall_journal.canonical(owners)).hexdigest()
            uninstall_journal.advance(journal_fd, "admitted", observation)
            return {"state": "admitted", "stage": pointer["stage"]}
        finally:
            os.close(journal_fd)
    finally:
        os.close(lock_fd)


def uninstall_stop_and_archive():
    """Replay the exact Rust Stop/seal/pointer subtransaction from intent."""
    need(sys.platform == "linux" and os.geteuid() == 0)
    journal_fd = uninstall_journal.directory()
    try:
        intent, phases = uninstall_journal.read(journal_fd)
        need(not phases or phases[0][0]["state"] == "admitted")
        if len(phases) >= 2:
            return {"state": phases[-1][0]["state"], "stage": intent["stage"]}
        binary = held_root_file(Path("/usr/local/bin/aegis-client"), 256 << 20,
                                (0o555, 0o755))
        try:
            need(file_sha(binary)[1] == intent["candidate_sha256"])
        finally:
            os.close(binary)
        if intent["boot_id"] != current_boot():
            # /run's old StageGuard is gone. The production fresh-boot
            # observer proves the historical capsule, current native deny,
            # stopped fixed client and absence of a private owner. It creates
            # no fictitious Stop seal and grants no activation.
            result = strict_json(call_output(
                ["/usr/local/bin/aegis-client", "auto-uninstall-observe-reboot"],
                maximum=8192, timeout=240))
            need(type(result) is dict and set(result) == {
                "schema", "stage", "old_boot_id", "new_boot_id",
                 "candidate_sha256", "pointer_sha256", "pointer_state",
                 "active_report_sha256",
                "boot_proof"} and
                 result["schema"] == "aegis_auto_v2_uninstall_reboot_observation_v1" and
                 result["stage"] == intent["stage"] and
                 result["old_boot_id"] == intent["boot_id"] and
                 result["new_boot_id"] == current_boot() and
                 result["candidate_sha256"] == intent["candidate_sha256"] and
                 result["pointer_sha256"] == intent["pointer_sha256"] and
                 result["pointer_state"] in ("pending", "stopped-sealed",
                                             "stopped-archived") and
                 type(result["boot_proof"]) is dict and
                 result["boot_proof"].get("schema") ==
                 "aegis_auto_v2_verified_boot_v1")
            if result["pointer_state"] == "pending":
                pointer, raw, owners, version, guard = _uninstall_source_facts(
                    expected_boot=intent["boot_id"])
                need(pointer["stage"] == intent["stage"] and
                     pointer["candidate_sha256"] == intent["candidate_sha256"] and
                     hashlib.sha256(raw).hexdigest() == intent["pointer_sha256"] and
                     hashlib.sha256(uninstall_journal.canonical(owners)).hexdigest() ==
                     intent["owner_manifest_sha256"] and
                     guard.get("content_sha256", hashlib.sha256(b"absent").hexdigest()) ==
                     intent["guard_config_sha256"] and
                     version == intent["version"])
            else:
                version = call_output(["/usr/bin/dpkg-query", "--show",
                    "--showformat=${Status}\n${Version}\n", "aegis-client"],
                    maximum=256, timeout=10).decode("ascii", "strict").splitlines()
                need(len(version) == 2 and version[0] == "install ok installed" and
                     version[1] == intent["version"])
            # Intent may have been fsynced before phase-000 admission. A
            # fresh-boot proof is the admission observation in that cut;
            # never reconstruct an old /run StageGuard or Stop receipt.
            if not phases:
                _intent, phases = uninstall_journal.advance(journal_fd,
                    "admitted", hashlib.sha256(
                        uninstall_journal.canonical(result)).hexdigest())
            uninstall_journal.advance(journal_fd, "reboot-observed",
                hashlib.sha256(uninstall_journal.canonical(result)).hexdigest())
            return {"state": "reboot-observed", "stage": intent["stage"]}
        need(phases and phases[0][0]["state"] == "admitted")
        need(call_output(["/usr/local/bin/aegis-client",
                          "auto-uninstall-stop-and-archive", intent["stage"]],
                         maximum=1024, timeout=120) == b"")
        control = control_directory()
        try:
            receipt_raw, _ = control_leaf(control, "generation-pointer-stopped.json")
            receipt = strict_json(receipt_raw)
            need(type(receipt) is dict and receipt.get("stage") == intent["stage"] and
                 receipt.get("pointer_sha256") == intent["pointer_sha256"] and
                 receipt.get("candidate_sha256") == intent["candidate_sha256"] and
                 current_pointer(control) is None)
        finally:
            os.close(control)
        observation = hashlib.sha256(receipt_raw).hexdigest()
        uninstall_journal.advance(journal_fd, "stopped-archived", observation)
        return {"state": "stopped-archived", "stage": intent["stage"]}
    finally:
        os.close(journal_fd)


def _open_original_lock(path, number, *, allow_uninstall=False, create=False):
    """Hold the existing original lock inode at its inherited descriptor number."""
    need(number in (9, 10))
    need(not create or allow_uninstall)
    try:
        os.fstat(number)
    except OSError as error:
        need(error.errno == 9)
    else:
        raise Refused()
    path = absolute(path)
    def isolated(fd):
        moved = fcntl.fcntl(fd, fcntl.F_DUPFD_CLOEXEC, 11)
        os.close(fd)
        return moved
    parent = isolated(os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC))
    try:
        for part in path.parts[1:-1]:
            child = isolated(os.open(part, os.O_RDONLY | os.O_DIRECTORY |
                                     os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent))
            info = os.fstat(child)
            need(stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == 0 and
                 not stat.S_IMODE(info.st_mode) & 0o022)
            os.close(parent)
            parent = child
        flags = os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
        if create:
            flags |= os.O_CREAT
        fd = isolated(os.open(path.name, flags, 0o600, dir_fd=parent))
        try:
            before = os.fstat(fd)
            named = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
            need(stat.S_ISREG(before.st_mode) and before.st_uid == before.st_gid == 0 and
                 before.st_nlink == 1 and before.st_size == 0 and
                 stat.S_IMODE(before.st_mode) == 0o600 and
                 (before.st_dev, before.st_ino) == (named.st_dev, named.st_ino))
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            if allow_uninstall:
                # Replays are allowed only for the durable typed journal.
                uninstall_intent_present()
            else:
                need(not uninstall_intent_present())
            os.dup2(fd, number, inheritable=True)
            return number
        finally:
            os.close(fd)
    finally:
        os.close(parent)


def _rotation_report(raw, schema):
    need(0 < len(raw) <= 128 * 1024)
    value = strict_json(raw)
    need(type(value) is dict and value.get("schema") == schema)
    return value


def _successor_report(raw, root, candidate_sha):
    value = _rotation_report(raw, "aegis_auto_v2_stopped_successor_verification_v1")
    need(set(value) == {"schema", "stopped", "successor"} and
         type(value["stopped"]) is dict and type(value["successor"]) is dict)
    next_stage = value["successor"]
    need(set(next_stage) == {"kind", "intent_sha256", "old_active_sha256",
                             "old_stopped_sha256", "next_public_payload_root",
                             "next_candidate_binary", "next_candidate_sha256",
                             "next_installer_sha256",
                             "next_bundle_manifest_sha256", "next_sums_sha256",
                             "prior_successor_intent_sha256"} and
         next_stage["kind"] == "upgrade" and
         next_stage["next_public_payload_root"] == str(root) and
         next_stage["next_candidate_binary"] == str(root / "bin/aegis-client") and
         next_stage["next_candidate_sha256"] == candidate_sha and
         all(type(next_stage[key]) is str and
             re.fullmatch("[0-9a-f]{64}", next_stage[key]) for key in
             ("intent_sha256", "old_active_sha256", "old_stopped_sha256",
              "next_candidate_sha256", "next_installer_sha256",
              "next_bundle_manifest_sha256", "next_sums_sha256")) and
         (next_stage["prior_successor_intent_sha256"] is None or
          (type(next_stage["prior_successor_intent_sha256"]) is str and
           re.fullmatch("[0-9a-f]{64}",
                        next_stage["prior_successor_intent_sha256"]))) and
         next_stage["next_installer_sha256"] ==
         hashlib.sha256(bounded_root_bytes(root / "install.sh", 4 << 20,
                                           (0o555,))).hexdigest() and
         next_stage["next_bundle_manifest_sha256"] ==
         hashlib.sha256(bounded_root_bytes(root / "bundle.manifest.json",
                                           4 << 20,(0o444,))).hexdigest() and
         next_stage["next_sums_sha256"] ==
         hashlib.sha256(bounded_root_bytes(root / "SHA256SUMS",
                                           4 << 20,(0o444,))).hexdigest())
    need(value["stopped"].get("stage", {}).get("mode") in
         ("socks-only", "wide-redirect-safe", "full-wide-tun"))
    return value


def _passive_package_source(root, candidate_sha, installed_sha=None):
    """Reopen the complete installed package against one retained release."""
    root = absolute(str(root))
    need(root.parent == Path("/var/lib/aegis-auto/releases") and
         re.fullmatch(r"[A-Za-z0-9-]{16,128}", root.name))
    rows = {}
    for leaf in FRESH_CLIENT_HELPERS:
        source_path, expected_mode = retained_client_helper_source(root, leaf)
        source = bounded_root_bytes(source_path, 4 << 20,
                                    (0o444, 0o555))
        mode = (0o644, 0o755) if leaf == "lib/root-state.sh" else (
            expected_mode,)
        need(bounded_root_bytes(Path("/usr/local/lib/aegis/helpers") / leaf,
                                4 << 20, mode) == source)
        rows["helper/" + leaf] = hashlib.sha256(source).hexdigest()
    for leaf in FRESH_CLIENT_UNITS:
        source = bounded_root_bytes(root / "packaging/systemd" / leaf,
                                    1 << 20, (0o444,))
        need(bounded_root_bytes(Path("/etc/systemd/system") / leaf,
                                1 << 20, (0o644,)) == source)
        rows["unit/" + leaf] = hashlib.sha256(source).hexdigest()
    need(hashlib.sha256(bounded_root_bytes("/usr/local/bin/aegis-client",
                                           512 << 20, (0o555, 0o755))).hexdigest() ==
         (candidate_sha if installed_sha is None else installed_sha))
    return hashlib.sha256(json.dumps(rows, sort_keys=True,
                                     separators=(",", ":")).encode()).hexdigest()


def _passive_successor_source(stopped):
    need(stopped["stage"]["mode"] == "socks-only")
    return _passive_package_source(stopped["input"]["public_payload_root"],
                                   stopped["input"]["candidate_sha256"])


def _passive_package_state(package):
    """Return only an exact signed-DEB package state, never infer it from files."""
    version = call_output(["/usr/bin/dpkg-deb", "--field", str(package), "Version"],
                          maximum=1024, timeout=10).strip()
    arch = call_output(["/usr/bin/dpkg-deb", "--field", str(package), "Architecture"],
                       maximum=1024, timeout=10).strip()
    need(version and arch and len(version) <= 80 and len(arch) <= 16)
    try:
        status = call_output(["/usr/bin/dpkg-query", "-W",
                              "--showformat=${Status}|${Version}|${Architecture}",
                              "aegis-client"], maximum=1024, timeout=10)
    except (Refused, OSError, subprocess.SubprocessError):
        return None
    prefix, separator, fields = status.partition(b"|")
    if not separator or fields != version + b"|" + arch:
        return None
    values = {
        b"install ok installed": "installed",
        b"install ok unpacked": "unpacked",
        b"install ok half-configured": "half-configured",
        b"install ok triggers-awaited": "triggers-awaited",
        b"install ok triggers-pending": "triggers-pending",
    }
    return values.get(prefix)


def _passive_package_complete(package):
    return _passive_package_state(package) == "installed"


def _passive_transition_locator():
    """Locate a fixed handoff only; Rust authenticates it before any effect."""
    raw = bounded_root_bytes(CONTROL / "generation-successor-current.json",
                             16384, (0o600,))
    value = strict_json(raw)
    root = value.get("next_public_payload_root")
    need(type(root) is str and re.fullmatch(
        r"/var/lib/aegis-auto/releases/[A-Za-z0-9-]{16,128}", root))
    return root


def _incoming_upgrade_coordinator(root):
    """Bind the executing B coordinator to its signed retained source row."""
    helper_name = "scripts/lib/aegis_installer_auto_v2.py"
    manifest = strict_json(bounded_root_bytes(root / "bundle.manifest.json",
                                              4 << 20, (0o444,)))
    need(Path(__file__).absolute() == root / helper_name and
         type(manifest.get("files")) is list and
         helper_name in manifest["files"])
    sums = bounded_root_bytes(root / "SHA256SUMS", 4 << 20,
                              (0o444,)).decode("ascii").splitlines()
    actual = hashlib.sha256(bounded_root_bytes(
        root / helper_name, 4 << 20, (0o444, 0o555))).hexdigest()
    need(f"{actual}  {helper_name}" in sums)


def _passive_transition_status(candidate, install_fd, root, candidate_sha):
    raw = call_output([str(candidate), "auto-passive-transition-status",
                       "--lock-fd", str(install_fd)], maximum=8192,
                      timeout=45, pass_fds=(install_fd,))
    value = strict_json(raw)
    need(type(value) is dict and set(value) == {
        "schema", "phase", "successor_intent_sha256", "candidate_sha256",
        "public_payload_root", "preinst_sha256", "old_install_sha256",
        "old_candidate_sha256", "old_public_payload_root"} and
        value["schema"] == "aegis_auto_v2_passive_transition_status_v1" and
        value["phase"] in ("pending-old", "package-installed", "new-active") and
        value["candidate_sha256"] == candidate_sha and
        value["public_payload_root"] == str(root) and
        all(type(value[key]) is str and re.fullmatch(r"[0-9a-f]{64}", value[key])
            for key in ("successor_intent_sha256", "preinst_sha256",
                        "old_install_sha256", "old_candidate_sha256")))
    return value


def _passive_guardian_report(operation, install_fd, schema, status):
    helper = "/usr/local/lib/aegis/helpers/lib/aegis_auto_guardian.py"
    value = strict_json(call_output(
        ["/usr/bin/python3", "-I", "-B", helper, operation, str(install_fd)],
        maximum=8192, timeout=45, pass_fds=(install_fd,)))
    need(type(value) is dict and value.get("schema") == schema and
         value.get("boot_id") == current_boot() and
         value.get("preinst_sha256") == status["preinst_sha256"] and
         value.get("candidate_sha256") == status["candidate_sha256"])
    return value


def _passive_resume_package(root, package, candidate, candidate_sha,
                            install_fd, status, progress):
    """Resume only the sealed A-to-B package, before any new Prepare."""
    package_state = _passive_package_state(package)
    if status["phase"] == "new-active":
        need(package_state == "installed" and
             _passive_package_source(root, candidate_sha))
        progress["phase"] = "package_terminal_readback"
        return "terminal_active"
    if package_state is None:
        need(status["phase"] == "pending-old")
        old = "/usr/local/bin/aegis-client"
        # DB absence is not proof that unpack never started. Require the
        # complete A executable/helper/unit roster and A INSTALL before
        # invoking preinst again; a mixed partially unpacked tree stays sticky.
        _passive_package_source(status["old_public_payload_root"],
                                status["old_candidate_sha256"])
        need(hashlib.sha256(bounded_root_bytes(
            "/var/lib/aegis-install/client/auto-guardian-install.json",
            8192, (0o600,))).hexdigest() == status["old_install_sha256"])
        old_proof = _rotation_report(call_output(
            [old, "verify-retired-passive-successor", "--lock-fd",
             str(install_fd)], maximum=128 << 10, timeout=30,
            pass_fds=(install_fd,)),
            "aegis_auto_v2_retired_passive_successor_verification_v1")
        need(old_proof["successor"]["next_public_payload_root"] == str(root) and
             old_proof["successor"]["next_candidate_sha256"] == candidate_sha and
             old_proof["successor"]["intent_sha256"] ==
             status["successor_intent_sha256"])
        progress["phase"] = "package_unpack"
        call_output(["/usr/bin/dpkg", "--force-confold", "--install", str(package)],
                    maximum=128 << 10, timeout=300, pass_fds=(install_fd,))
        package_state = _passive_package_state(package)
    elif package_state in ("unpacked", "half-configured",
                           "triggers-awaited", "triggers-pending"):
        need(status["phase"] in ("pending-old", "package-installed"))
        _passive_package_source(root, candidate_sha)
        staged = _passive_guardian_report(
            "passive-successor-staged-readback", install_fd,
            "aegis_auto_guard_passive_successor_staged_v1", status)
        need(staged.get("old_install_sha256") == status["old_install_sha256"] and
             staged.get("no_live_actors") is True)
        progress["phase"] = "package_configure"
        call_output(["/usr/bin/dpkg", "--configure", "aegis-client"],
                    maximum=128 << 10, timeout=300, pass_fds=(install_fd,))
        package_state = _passive_package_state(package)
    need(package_state == "installed")
    parent = control_directory()
    try:
        current = current_pointer(parent)
    finally:
        os.close(parent)
    if current is not None:
        need(current[0]["candidate_sha256"] == candidate_sha and
             current[0]["boot_id"] == current_boot())
        return "current_pending"
    _passive_package_source(root, candidate_sha)
    current_install = bounded_root_bytes(
        "/var/lib/aegis-install/client/auto-guardian-install.json",
        8192, (0o600,))
    if hashlib.sha256(current_install).hexdigest() == status["old_install_sha256"]:
        staged = _passive_guardian_report(
            "passive-successor-staged-readback", install_fd,
            "aegis_auto_guard_passive_successor_staged_v1", status)
        need(staged.get("old_install_sha256") == status["old_install_sha256"] and
             staged.get("no_live_actors") is True)
        progress["phase"] = "package_admit_guard"
        call_output(["/usr/bin/python3", "-I", "-B",
                     "/usr/local/lib/aegis/helpers/lib/aegis_auto_guardian.py",
                     "admit-passive-successor", str(install_fd)],
                    maximum=8192, timeout=45, pass_fds=(install_fd,))
    progress["phase"] = "package_actor_progress"
    observed = _passive_guardian_report(
        "passive-successor-progress-readback", install_fd,
        "aegis_auto_guard_passive_successor_progress_v1", status)
    fixed = {unit for unit, _, _ in PASSIVE_ACTORS}
    need(type(observed.get("active")) is list and
         type(observed.get("missing")) is list and
         len(observed["active"] + observed["missing"]) == len(fixed) and
         set(observed["active"] + observed["missing"]) == fixed and
         len(set(observed["active"] + observed["missing"])) == len(fixed))
    progress["phase"] = "package_resume"
    call_output(["/bin/bash", str(root / "install.sh"), "client",
                 "--resume-v2-upgrade"], maximum=128 << 10, timeout=300,
                pass_fds=(install_fd,))
    after = _passive_guardian_report(
        "passive-successor-progress-readback", install_fd,
        "aegis_auto_guard_passive_successor_progress_v1", status)
    need(after.get("missing") == [] and set(after.get("active", [])) == fixed)
    return "ready_for_prepare"


def _passive_finish_prepare(root, candidate, requested_mode, progress):
    progress["phase"] = "package_install"
    install_args = ["/usr/bin/python3", "-I", "-B",
        "/usr/local/lib/aegis/helpers/lib/aegis_installer_auto_v2.py",
        "install", "--config-root", "/etc/aegis/client", "--state-dir",
        "/var/lib/aegis-client", "--metadata-dir", "/var/lib/aegis-install/auto-client",
        "--staging-parent", "/run/aegis-installer-config-snapshots",
        "--public-payload-root", str(root), "--candidate-binary", str(candidate),
        "--installed-binary", "/usr/local/bin/aegis-client", "--runtime-events",
        str(AUTO_RUNTIME_EVENTS),
        "--existing-choice", "upgrade"]
    if requested_mode is not None:
        install_args.extend(("--requested-mode", requested_mode))
    need(strict_json(call_output(install_args, maximum=8192, timeout=960)) ==
         {"status": "terminal_active"})
    return _passive_completed_active(root, hashlib.sha256(bounded_root_bytes(
        candidate, 512 << 20, (0o555,))).hexdigest(), advance=True)


def _passive_compensated_readback(candidate, root, candidate_sha, status):
    """Reopen genuine rolled-back A roots under a fresh original InstallLock."""
    value = strict_json(call_output(
        [str(candidate), "auto-verify-passive-compensated"],
        maximum=8192, timeout=120))
    need(type(value) is dict and set(value) == {
        "schema", "successor_intent_sha256", "preinst_sha256",
        "candidate_sha256", "old_candidate_sha256", "public_payload_root",
        "stage", "stage_device", "stage_inode", "pointer_sha256",
        "certificate_sha256"} and
        value["schema"] == "aegis_auto_v2_passive_compensated_readback_v1" and
        value["successor_intent_sha256"] == status["successor_intent_sha256"] and
        value["preinst_sha256"] == status["preinst_sha256"] and
        value["candidate_sha256"] == candidate_sha and
        value["old_candidate_sha256"] == status["old_candidate_sha256"] and
        value["public_payload_root"] == str(root) and
        type(value["stage"]) is str and value["stage"].startswith("/") and
        type(value["stage_device"]) is int and value["stage_device"] > 0 and
        type(value["stage_inode"]) is int and value["stage_inode"] > 0 and
        all(type(value[key]) is str and re.fullmatch(r"[0-9a-f]{64}", value[key])
            for key in ("pointer_sha256", "certificate_sha256")))
    return value


def _passive_unsealed_stopped_readback(candidate, root, candidate_sha, status):
    """Fresh own-lock proof of B's stopped, published unsealed generation."""
    value = strict_json(call_output(
        [str(candidate), "auto-verify-passive-unsealed-stopped"],
        maximum=8192, timeout=120))
    need(type(value) is dict and set(value) == {
        "schema", "kind", "successor_intent_sha256", "preinst_sha256",
        "candidate_sha256", "old_candidate_sha256", "public_payload_root",
        "stage", "stopped_report_sha256", "pointer_sha256",
        "certificate_sha256"} and
        value["schema"] == "aegis_auto_v2_passive_unsealed_stopped_readback_v1" and
        value["kind"] == "unsealed-finalized-stopped" and
        value["successor_intent_sha256"] == status["successor_intent_sha256"] and
        value["preinst_sha256"] == status["preinst_sha256"] and
        value["candidate_sha256"] == candidate_sha and
        value["old_candidate_sha256"] == status["old_candidate_sha256"] and
        value["public_payload_root"] == str(root) and
        type(value["stage"]) is str and value["stage"].startswith("/") and
        all(type(value[key]) is str and re.fullmatch(r"[0-9a-f]{64}", value[key])
            for key in ("stopped_report_sha256", "pointer_sha256",
                        "certificate_sha256")))
    return value


def _passive_resume_unsealed(candidate, root, candidate_sha, status,
                             certificate=None):
    """Retire only the exact B unsealed recovery through its own-lock journal."""
    value = strict_json(call_output(
        [str(candidate), "auto-resume-passive-unsealed-stopped"],
        maximum=8192, timeout=120))
    need(type(value) is dict and set(value) == {
        "schema", "outcome", "successor_intent_sha256", "preinst_sha256",
        "candidate_sha256", "stage", "recovery_sha256",
        "certificate_sha256", "journal_sha256"} and
        value["schema"] == "aegis_auto_v2_passive_unsealed_resume_readback_v1" and
        value["outcome"] == "resumed" and
        value["successor_intent_sha256"] == status["successor_intent_sha256"] and
        value["preinst_sha256"] == status["preinst_sha256"] and
        value["candidate_sha256"] == candidate_sha and
        type(value["stage"]) is str and value["stage"].startswith("/") and
        all(type(value[key]) is str and re.fullmatch(r"[0-9a-f]{64}", value[key])
            for key in ("recovery_sha256", "certificate_sha256",
                        "journal_sha256")) and
        (certificate is None or
         (value["stage"] == certificate["stage"] and
          value["certificate_sha256"] == certificate["certificate_sha256"])))
    return value


def _passive_unsealed_certificate_present(status):
    successor = status["successor_intent_sha256"]
    need(type(successor) is str and re.fullmatch(r"[0-9a-f]{64}", successor))
    leaf = CONTROL / f"passive-unsealed-stopped-{successor}.json"
    need(not leaf.is_symlink())
    return leaf.exists()


def _passive_completed_active(root, candidate_sha, *, advance):
    """Fresh live B proof; retire A-to-B fixed names on the same boot."""
    installed = "/usr/local/bin/aegis-client"
    observed = strict_json(call_output(
        [installed, "auto-verify-current-socks"], maximum=8192, timeout=45))
    need(type(observed) is dict and set(observed) == {
        "schema", "stage", "public_payload_root", "candidate_sha256"} and
        observed["schema"] == "aegis_auto_v2_current_socks_active_v1" and
        observed["public_payload_root"] == str(root) and
        observed["candidate_sha256"] == candidate_sha)
    parent = control_directory()
    try:
        pointer = current_pointer(parent)
        need(pointer is not None and pointer[0]["stage"] == observed["stage"] and
             pointer[0]["candidate_sha256"] == candidate_sha and
             pointer[0]["boot_id"] == current_boot())
    finally:
        os.close(parent)
    if advance:
        outcome = strict_json(call_output(
            [installed, "auto-advance-completed-passive-transition"],
            maximum=8192, timeout=120))
        need(type(outcome) is dict and outcome.get("schema") ==
             "aegis_auto_v2_passive_transition_advance_v1" and
             outcome.get("outcome") == "archived" and
             not (CONTROL / "passive-package-preinst.json").exists() and
             not (CONTROL / PASSIVE_SUCCESSOR_INTENT).exists())
    return "terminal_active"


def _current_mode_hint():
    """Historical mode selects a route only; live Rust proof authorizes Socks."""
    raw = bounded_root_bytes(CONTROL / "generation.json", 128 << 10, (0o600,))
    value = strict_json(raw)
    need(type(value) is dict and type(value.get("report")) is dict and
         type(value["report"].get("stage")) is dict)
    mode = value["report"]["stage"].get("mode")
    need(mode in ("socks-only", "wide-redirect-safe", "full-wide-tun"))
    return mode


def _passive_continue(root, package, candidate, candidate_sha,
                      requested_mode, progress):
    """Consume the same protected A-to-B handoff after any package cut."""
    install_fd = _open_original_lock("/run/aegis-auto-install.lock", 9)
    try:
        progress["phase"] = "package_retry_status"
        status = _passive_transition_status(candidate, 9, root, candidate_sha)
        # A retained stopped certificate locates an interrupted recovery only
        # while B has no active seal. Once B is freshly sealed, the typed
        # transition status and active inspector must drive terminal handoff.
        if (status["phase"] != "new-active" and
                _passive_unsealed_certificate_present(status)):
            os.close(install_fd)
            install_fd = None
            progress["phase"] = "package_compensated"
            _passive_resume_unsealed(candidate, root, candidate_sha, status)
            install_fd = _open_original_lock("/run/aegis-auto-install.lock", 9)
            refreshed = _passive_transition_status(candidate, 9, root,
                                                    candidate_sha)
            need(all(refreshed[key] == status[key] for key in status
                     if key != "phase"))
            status = refreshed
        outcome = _passive_resume_package(root, package, candidate, candidate_sha,
                                          9, status, progress)
    finally:
        if install_fd is not None:
            os.close(install_fd)
    if outcome == "terminal_active":
        return _passive_completed_active(root, candidate_sha, advance=True)
    if outcome == "current_pending":
        progress["phase"] = "package_compensated"
        recovered = recover_current(candidate)
        if recovered == "recovered":
            _passive_compensated_readback(candidate, root, candidate_sha, status)
            # Rollback restores A executable. Genuine new Prepare publishes B.
            installed_sha = status["old_candidate_sha256"]
        elif recovered == "recovered_stopped":
            certificate = _passive_unsealed_stopped_readback(
                candidate, root, candidate_sha, status)
            _passive_resume_unsealed(candidate, root, candidate_sha, status,
                                     certificate)
            # Finalized recovery leaves a stopped B published source, not A.
            installed_sha = candidate_sha
        else:
            raise Refused()
        _passive_package_source(root, candidate_sha, installed_sha=installed_sha)
        need(_passive_package_state(package) == "installed")
        install_fd = _open_original_lock("/run/aegis-auto-install.lock", 9)
        try:
            refreshed = _passive_transition_status(candidate, 9, root, candidate_sha)
            need(refreshed == status or
                 (refreshed["phase"] == "pending-old" and
                  all(refreshed[key] == status[key] for key in status
                      if key != "phase")))
        finally:
            os.close(install_fd)
        outcome = "ready_for_prepare"
    need(outcome == "ready_for_prepare")
    return _passive_finish_prepare(root, candidate, requested_mode, progress)


def _passive_actor_start_tick(pid):
    need(type(pid) is int and pid > 1)
    with open(f"/proc/{pid}/stat", "rb", buffering=0) as source:
        raw = source.read(4096)
    need(raw and len(raw) <= 4096 and b") " in raw)
    tail = raw.rsplit(b") ", 1)[1].split()
    need(len(tail) > 19)
    value = int(tail[19])
    need(value > 0)
    return value


def _passive_old_actors_gone(intent):
    for unit, facts in intent["actors"].items():
        pid = int(facts["MainPID"])
        try:
            current = _passive_actor_start_tick(pid)
        except (FileNotFoundError, ProcessLookupError):
            continue
        need(current != intent["actor_start_ticks"][unit])


def _passive_non_actor_stopped(deadline=None, *, before_retirement=False):
    """Old pinned guardian independently reads capture and static PID1 state."""
    deadline = deadline or time.monotonic() + 20.0
    _remaining(deadline, 20)
    source = Path("/usr/local/lib/aegis/helpers/lib/aegis_auto_guardian.py")
    spec = importlib.util.spec_from_file_location("aegis_passive_retired_source", source)
    need(spec is not None and spec.loader is not None)
    guardian = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(guardian)
    guardian.own_source()
    _remaining(deadline, 20)
    if before_retirement:
        facts = guardian._rotation_actor_facts(
            "aegis-auto-capture-topology.service", deadline=deadline)
        need(facts["ActiveState"] == "inactive" and facts["SubState"] == "dead" and
             facts["MainPID"] == "0" and facts["ControlPID"] == "0" and
             facts["NFileDescriptorStore"] == "0" and
             facts["ControlGroup"] in ("", "/system.slice/aegis-auto-capture-topology.service"))
        if facts["ControlGroup"]:
            group = Path("/sys/fs/cgroup") / facts["ControlGroup"].lstrip("/")
            need(not group.exists() or group.joinpath("cgroup.procs").read_text() == "")
    else:
        guardian._rotation_actors_stopped(deadline)
    guardian._rotation_static_stopped(deadline)


def _retired_passive_actor_status(intent, deadline=None):
    """Only this sealed package intent permits four retained inactive IDs."""
    no_private_jobs_or_units(deadline)
    active, missing = [], []
    for unit, socket_path, source_name in PASSIVE_ACTORS:
        raw = call_output(["/usr/bin/systemctl", "show", unit, "--no-pager",
                           *sum((("-p", name) for name in (
                               "Id", "LoadState", "ActiveState", "SubState", "MainPID",
                               "ControlPID", "ControlGroup", "InvocationID",
                               "NeedDaemonReload", "NFileDescriptorStore")), ())],
                          maximum=4096, timeout=_remaining(deadline, 5))
        facts = {}
        for line in raw.decode("ascii").splitlines():
            key, sep, value = line.partition("=")
            need(sep and key not in facts)
            facts[key] = value
        prior = intent["actors"][unit]
        need(set(facts) == set(prior) and facts["Id"] == unit and
             facts["LoadState"] == "loaded" and
             facts["NeedDaemonReload"] == "no" and
             facts["ControlPID"] == "0" and facts["NFileDescriptorStore"] == "0")
        if facts["ActiveState"] == "inactive":
            need(facts["SubState"] == "dead" and facts["MainPID"] == "0" and
                 facts["ControlGroup"] == "" and
                 facts["InvocationID"] in
                 ("", "0" * 32, prior["InvocationID"]) and
                 not os.path.lexists(socket_path))
            missing.append(unit)
        else:
            need(facts == prior and facts["ActiveState"] == "active" and
                 facts["SubState"] == "running" and
                 facts["ControlGroup"] == "/system.slice/" + unit)
            pid = int(facts["MainPID"])
            need(pid > 1 and _passive_actor_start_tick(pid) ==
                 intent["actor_start_ticks"][unit] and
                 Path(f"/proc/{pid}/cgroup").read_text() ==
                 "0::/system.slice/" + unit + "\n")
            with open(f"/proc/{pid}/cmdline", "rb", buffering=0) as process:
                need(process.read(1025) ==
                     ("/usr/bin/python3\0-I\0-B\0/usr/local/lib/aegis/helpers/lib/" +
                      source_name + "\0serve\0").encode())
            actor_socket_owner(Path(socket_path), pid)
            active.append((unit, socket_path, facts))
    return active, missing


def _passive_retirement_readback():
    """Fresh PID1, source and sealed receipt evidence after old actor Stop."""
    deadline = time.monotonic() + 23.0
    parent = _passive_control()
    try:
        intent = _passive_record(parent, PASSIVE_SUCCESSOR_INTENT)
        retired = _passive_record(parent, PASSIVE_SUCCESSOR_RETIRED)
        need(type(intent) is dict and type(retired) is dict and
             set(intent) == {"schema", "boot_id", "successor_sha256",
                             "successor_intent_sha256",
                             "stopped_sha256", "source_sha256", "actors",
                             "actor_start_ticks"} and
             intent["schema"] == "aegis_auto_v2_passive_successor_retirement_intent_v1" and
             type(intent["actors"]) is dict and
             set(intent["actors"]) == {row[0] for row in PASSIVE_ACTORS} and
             type(intent["actor_start_ticks"]) is dict and
             set(intent["actor_start_ticks"]) == set(intent["actors"]) and
             set(retired) == {"schema", "boot_id", "intent_sha256",
                              "stopped_successor_sha256", "source_sha256",
                              "no_live_actors", "non_actor_units_stopped"} and
             retired["schema"] == "aegis_auto_v2_passive_successor_retired_v1" and
             retired["boot_id"] == intent["boot_id"] == current_boot() and
             retired["intent_sha256"] == hashlib.sha256(
                 bounded_root_bytes(CONTROL / PASSIVE_SUCCESSOR_INTENT,
                                    16384, (0o600,))).hexdigest() and
             retired["stopped_successor_sha256"] == intent["successor_sha256"] and
             retired["source_sha256"] == intent["source_sha256"] and
             retired["no_live_actors"] is True and
             retired["non_actor_units_stopped"] is True)
        for value in (intent["successor_sha256"], intent["successor_intent_sha256"],
                      intent["stopped_sha256"],
                      intent["source_sha256"]):
            need(type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value))
        invocations = {}
        for unit, facts in intent["actors"].items():
            need(type(facts) is dict and type(facts.get("InvocationID")) is str and
                 re.fullmatch(r"[0-9a-fA-F]{32}", facts["InvocationID"]) and
                 type(intent["actor_start_ticks"][unit]) is int and
                 intent["actor_start_ticks"][unit] > 0)
            invocations[unit] = facts["InvocationID"]
        saved, missing = _retired_passive_actor_status(intent, deadline)
        need(not saved and set(missing) == set(invocations))
        _passive_old_actors_gone(intent)
        need(all(not os.path.lexists(socket_path) for _, socket_path, _ in PASSIVE_ACTORS))
        stopped_raw = bounded_root_bytes(CONTROL / "generation-passive-old-stopped.json",
                                         128 << 10, (0o600,))
        need(stopped_raw.endswith(b"\n") and not stopped_raw.endswith(b"\n\n") and
             hashlib.sha256(stopped_raw[:-1]).hexdigest() ==
             intent["stopped_sha256"] and
             stopped_raw == (json.dumps(strict_json(stopped_raw), sort_keys=True,
                                        separators=(",", ":")) + "\n").encode())
        source = _passive_successor_source(strict_json(stopped_raw))
        need(source == intent["source_sha256"])
        _passive_non_actor_stopped(deadline)
        _remaining(deadline, 1)
        return retired
    finally:
        os.close(parent)


def _ensure_passive_old_stopped_report(intent, install_fd):
    """Repair only the pre-effect cut between intent and old report writes."""
    leaf = CONTROL / "generation-passive-old-stopped.json"
    if leaf.exists() or leaf.is_symlink():
        raw = bounded_root_bytes(leaf, 128 << 10, (0o600,))
        need(raw.endswith(b"\n") and not raw.endswith(b"\n\n") and
             hashlib.sha256(raw[:-1]).hexdigest() == intent["stopped_sha256"] and
             raw == (json.dumps(strict_json(raw), sort_keys=True,
                                separators=(",", ":")) + "\n").encode())
        return
    saved, missing = _retired_passive_actor_status(intent)
    need(not missing and len(saved) == len(PASSIVE_ACTORS))
    successor_raw = call_output(
        ["/usr/local/bin/aegis-client", "verify-stopped-successor", "--lock-fd",
         str(install_fd)], maximum=128 << 10, timeout=45, pass_fds=(install_fd,))
    need(hashlib.sha256(successor_raw).hexdigest() == intent["successor_sha256"])
    report = strict_json(successor_raw)
    stopped = report["stopped"]
    raw = (json.dumps(stopped, sort_keys=True, separators=(",", ":")) + "\n").encode()
    need(hashlib.sha256(raw[:-1]).hexdigest() == intent["stopped_sha256"] and
         _passive_successor_source(stopped) == intent["source_sha256"])
    parent = _passive_control()
    try:
        atomic_exclusive_bytes(parent, "generation-passive-old-stopped.json", raw)
    finally:
        os.close(parent)
    need(bounded_root_bytes(leaf, 128 << 10, (0o600,)) == raw)


def _authenticate_passive_retirement_before_stop(intent, install_fd):
    """An existing write-ahead intent never grants Stop without all pins."""
    need(type(intent) is dict and set(intent) ==
         {"schema", "boot_id", "successor_sha256", "successor_intent_sha256",
          "stopped_sha256", "source_sha256", "actors", "actor_start_ticks"} and
         intent["schema"] == "aegis_auto_v2_passive_successor_retirement_intent_v1" and
         intent["boot_id"] == current_boot() and
         set(intent["actors"]) == {unit for unit, _, _ in PASSIVE_ACTORS} and
         set(intent["actor_start_ticks"]) == set(intent["actors"]))
    successor_raw = bounded_root_bytes(CONTROL / "generation-successor-current.json",
                                       16384, (0o600,))
    successor = strict_json(successor_raw)
    stopped_raw = bounded_root_bytes(CONTROL / "generation-passive-old-stopped.json",
                                     128 << 10, (0o600,))
    verified_raw = call_output(
        ["/usr/local/bin/aegis-client", "verify-passive-retirement-intent",
         "--lock-fd", str(install_fd)], maximum=128 << 10, timeout=30,
        pass_fds=(install_fd,))
    verified = strict_json(verified_raw)
    need(stopped_raw.endswith(b"\n") and not stopped_raw.endswith(b"\n\n") and
         hashlib.sha256(stopped_raw[:-1]).hexdigest() == intent["stopped_sha256"] and
         stopped_raw == (json.dumps(strict_json(stopped_raw), sort_keys=True,
                                    separators=(",", ":")) + "\n").encode() and
         hashlib.sha256(successor_raw).hexdigest() ==
         intent["successor_intent_sha256"] and
         successor["schema"] == "aegis_auto_v2_stopped_successor_v1" and
         successor["kind"] == "upgrade" and
         hashlib.sha256(verified_raw).hexdigest() == intent["successor_sha256"] and
         verified["schema"] == "aegis_auto_v2_stopped_successor_verification_v1" and
         verified["successor"]["intent_sha256"] ==
         intent["successor_intent_sha256"] and
         verified["stopped"] == strict_json(stopped_raw) and
         successor["old_boot_id"] == intent["boot_id"] and
         _passive_successor_source(strict_json(stopped_raw)) ==
         intent["source_sha256"])
    for unit, _, _ in PASSIVE_ACTORS:
        facts = intent["actors"][unit]
        need(type(facts) is dict and facts["Id"] == unit and
             facts["ActiveState"] == "active" and facts["SubState"] == "running" and
             facts["ControlGroup"] == "/system.slice/" + unit and
             type(intent["actor_start_ticks"][unit]) is int and
             intent["actor_start_ticks"][unit] > 0)


def retire_passive_successor(install_fd):
    """Retire only the sealed old SOCKS actors under the original InstallLock."""
    fresh_package_lock(install_fd)
    old = "/usr/local/bin/aegis-client"
    parent = _passive_control()
    try:
        intent = _passive_record(parent, PASSIVE_SUCCESSOR_INTENT)
        if intent is None:
            successor_raw = call_output(
                [old, "verify-stopped-successor", "--lock-fd", str(install_fd)],
                maximum=128 << 10, timeout=45, pass_fds=(install_fd,))
            report = strict_json(successor_raw)
            need(report["schema"] == "aegis_auto_v2_stopped_successor_verification_v1" and
                 report["stopped"]["stage"]["mode"] == "socks-only")
            guardian_ready(old, "passive")
            source = _passive_successor_source(report["stopped"])
            saved, missing = passive_actor_status()
            need(not missing and len(saved) == len(PASSIVE_ACTORS))
            actors = {unit: facts for unit, _, facts in saved}
            actor_start_ticks = {unit: _passive_actor_start_tick(int(facts["MainPID"]))
                                 for unit, _, facts in saved}
            intent = {"schema": "aegis_auto_v2_passive_successor_retirement_intent_v1",
                      "boot_id": current_boot(),
                      "successor_sha256": hashlib.sha256(successor_raw).hexdigest(),
                      "successor_intent_sha256": report["successor"]["intent_sha256"],
                      "stopped_sha256": hashlib.sha256(json.dumps(
                          report["stopped"], sort_keys=True,
                          separators=(",", ":")).encode()).hexdigest(),
                      "source_sha256": source, "actors": actors,
                      "actor_start_ticks": actor_start_ticks}
            _passive_write(parent, PASSIVE_SUCCESSOR_INTENT, intent)
            # The source-bound stopped report is retained for after-Stop
            # revalidation; never reconstruct it from caller JSON.
            atomic_exclusive_bytes(parent, "generation-passive-old-stopped.json",
                                   (json.dumps(report["stopped"], sort_keys=True,
                                               separators=(",", ":")) + "\n").encode())
        else:
            need(intent["boot_id"] == current_boot())
        _ensure_passive_old_stopped_report(intent, install_fd)
        _authenticate_passive_retirement_before_stop(intent, install_fd)
        # An active rollback timer or capture actor is a recovery condition,
        # never a service to normalize by stopping it for package replacement.
        _passive_non_actor_stopped(before_retirement=True)
        saved, _ = _retired_passive_actor_status(intent)
        for unit, _, facts in saved:
            need(facts == intent["actors"][unit])
        pidfds = {}
        try:
            for unit, _, facts in saved:
                pidfds[unit] = os.pidfd_open(int(facts["MainPID"]), 0)
            for unit, handle in pidfds.items():
                poller = select.poll()
                poller.register(handle, select.POLLIN | select.POLLHUP | select.POLLERR)
                need(not poller.poll(0) and
                     _passive_actor_start_tick(int(intent["actors"][unit]["MainPID"])) ==
                     intent["actor_start_ticks"][unit])
            for unit, _, _ in reversed(PASSIVE_ACTORS):
                if unit in pidfds:
                    call_output(["/usr/bin/systemctl", "stop", unit],
                                maximum=1024, timeout=30)
                    poller = select.poll()
                    poller.register(pidfds[unit], select.POLLIN | select.POLLHUP | select.POLLERR)
                    need(poller.poll(1000))
        finally:
            for handle in pidfds.values():
                os.close(handle)
        _, missing = _retired_passive_actor_status(intent)
        need(set(missing) == set(intent["actors"]) and
             all(not os.path.lexists(socket_path) for _, socket_path, _ in PASSIVE_ACTORS))
        _passive_old_actors_gone(intent)
        _passive_non_actor_stopped()
        need(_passive_successor_source(strict_json(bounded_root_bytes(
            CONTROL / "generation-passive-old-stopped.json", 128 << 10,
            (0o600,)))) == intent["source_sha256"])
        retired = {"schema": "aegis_auto_v2_passive_successor_retired_v1",
                   "boot_id": intent["boot_id"],
                   "intent_sha256": hashlib.sha256(bounded_root_bytes(
                       CONTROL / PASSIVE_SUCCESSOR_INTENT, 16384, (0o600,))).hexdigest(),
                   "stopped_successor_sha256": intent["successor_sha256"],
                   "source_sha256": intent["source_sha256"],
                   "non_actor_units_stopped": True,
                   "no_live_actors": True}
        if _passive_record(parent, PASSIVE_SUCCESSOR_RETIRED) is None:
            _passive_write(parent, PASSIVE_SUCCESSOR_RETIRED, retired)
        need(_passive_retirement_readback() == retired)
        fresh_package_lock(install_fd)
        return retired
    finally:
        os.close(parent)


def _resume_terminal_migration_install(root, candidate, requested_mode, progress):
    args = ['/usr/bin/python3','-I','-B',
            '/usr/local/lib/aegis/helpers/lib/aegis_installer_auto_v2.py',
            'install','--config-root','/etc/aegis/client','--state-dir',
            '/var/lib/aegis-client','--metadata-dir',
            '/var/lib/aegis-install/auto-client','--staging-parent',
            '/run/aegis-installer-config-snapshots','--public-payload-root',
            str(root),'--candidate-binary',str(candidate),
            '--installed-binary','/usr/local/bin/aegis-client',
            '--runtime-events',str(AUTO_RUNTIME_EVENTS),
            '--existing-choice','upgrade']
    if requested_mode is not None:
        args.extend(('--requested-mode',requested_mode))
    progress['phase'] = 'terminal_migration_resume_install'
    result = strict_json(call_output(args,maximum=8192,timeout=960))
    need(result == {'status':'terminal_active'})
    return 'terminal_active'


def _resume_retired_terminal_rotation(root, package, candidate,
                                      candidate_sha, package_sha,
                                      requested_mode, progress):
    """Recover the durable retired rotation cut before registrar pending."""
    retired_path = Path('/var/lib/aegis-install/client/auto-guard-rotation-retired.json')
    if not retired_path.exists() and not retired_path.is_symlink():
        return None
    need(not retired_path.is_symlink())
    parent = control_directory()
    try:
        if current_pointer(parent) is not None:
            return None
    finally:
        os.close(parent)
    install_fd = guard_fd = None
    try:
        install_fd = _open_original_lock('/run/aegis-auto-install.lock',9)
        guard_fd = _open_original_lock(
            '/var/lib/aegis-install/client/device-guard.conf.lock',10)
        old = '/usr/local/bin/aegis-client'
        progress['phase'] = 'terminal_migration_retired_readback'
        retired = _rotation_report(call_output(
            [old,'verify-retired-successor','--lock-fd','9',
             '--guard-fd','10'],maximum=128 << 10,timeout=45,
            pass_fds=(9,10)),
            'aegis_auto_v2_retired_successor_verification_v1')
        need(set(retired) == {'schema','stopped','successor','retired'})
        if (retired['successor']['next_public_payload_root'] != str(root) or
            retired['successor']['next_candidate_binary'] != str(candidate) or
            retired['successor']['next_candidate_sha256'] != candidate_sha):
            # A completed predecessor can leave immutable retired receipts.
            # The ordinary Rust successor path must authenticate any new one.
            return None
        need(
             retired['retired'].get('no_live_actors') is True and
             retired['stopped']['stage']['mode'] != 'socks-only' and
             requested_mode != 'socks-only')
        unit = retired['stopped']['terminal']['private_unit']
        need(type(unit) is str and
             re.fullmatch(r'aegis-auto@[0-9a-f]{64}\.service',unit))
        progress['phase'] = 'terminal_migration_retired_prepare'
        prepared = strict_json(call_output(
            ['/usr/bin/python3','-I','-B',
             '/usr/local/lib/aegis/helpers/lib/aegis_auto_terminal_register.py',
             'migration-prepare',unit,str(root),candidate_sha,
             package_sha,'9','10'],maximum=4096,timeout=120,pass_fds=(9,10)))
        need(prepared.get('schema') == 'aegis_auto_terminal_migration_prepare_v1' and
             prepared.get('status') == 'prepared' and
             prepared.get('candidate_sha256') == candidate_sha and
             type(prepared.get('intent_sha256')) is str and
             re.fullmatch(r'[0-9a-f]{64}',prepared['intent_sha256']))
    finally:
        if guard_fd is not None: os.close(guard_fd)
        if install_fd is not None: os.close(install_fd)
    return _resume_terminal_migration(root,package,candidate,candidate_sha,
                                      package_sha,requested_mode,progress)


def _completed_terminal_migration(root, package_sha, candidate_sha):
    """Locate only a committed successor whose package installation may retry."""
    directory = Path('/var/lib/aegis-install/client/terminal-migrations')
    head_path = directory / 'head.json'
    if not head_path.exists() and not head_path.is_symlink():
        return None
    head_raw = bounded_root_bytes(head_path,4096,(0o600,))
    head = strict_json(head_raw)
    need(head_raw == uninstall_journal.canonical(head) + b'\n' and
         type(head) is dict and set(head) == {'schema','edge_sha256'} and
         head['schema'] == 'aegis_auto_terminal_migration_head_v1' and
         type(head['edge_sha256']) is str and
         re.fullmatch(r'[0-9a-f]{64}',head['edge_sha256']))
    edge_sha = head['edge_sha256']
    edge_raw = bounded_root_bytes(directory/('edge-'+edge_sha+'.json'),8192,(0o600,))
    edge = strict_json(edge_raw)
    need(edge_raw == uninstall_journal.canonical(edge) + b'\n' and
         hashlib.sha256(edge_raw).hexdigest() == edge_sha and
         type(edge) is dict and set(edge) == {
         'schema','old_source_sha256','new_source_sha256',
         'old_context_sha256','prior_head_sha256','candidate_sha256',
         'package_sha256','intent_sha256','new_install_sha256',
         'next_bundle_manifest_sha256','next_sums_sha256',
         'observer_runtime_sha256','new_observer_orphan_sha256s'} and
         edge['schema'] == 'aegis_auto_terminal_migration_edge_v1')
    orphans=edge['new_observer_orphan_sha256s']
    need(type(orphans) is list and len(orphans)<=8 and
         orphans==sorted(set(orphans)) and
         all(type(item) is str and re.fullmatch(r'[0-9a-f]{64}',item)
             for item in orphans))
    old_runtime=bounded_root_bytes(directory/(
        'observer-runtime-'+edge['intent_sha256']+'.json'),16384,(0o600,))
    need(hashlib.sha256(old_runtime).hexdigest()==
         edge['observer_runtime_sha256'])
    for orphan_sha in orphans:
        orphan=bounded_root_bytes(directory/(
            'observer-new-orphan-'+edge['intent_sha256']+'-'+orphan_sha+'.json'),
            16384,(0o600,))
        need(hashlib.sha256(orphan).hexdigest()==orphan_sha)
    if (edge['candidate_sha256'] != candidate_sha or
            edge['package_sha256'] != package_sha):
        return None
    complete_raw = bounded_root_bytes(directory/('complete-'+edge_sha+'.json'),
                                      8192,(0o600,))
    complete = strict_json(complete_raw)
    need(complete == {'schema':'aegis_auto_terminal_migration_complete_v1',
                      'intent_sha256':edge['intent_sha256'],
                      'edge_sha256':edge_sha,
                      'new_source_sha256':edge['new_source_sha256'],
                      'candidate_sha256':candidate_sha} and
         complete_raw == uninstall_journal.canonical(complete) + b'\n' and
         hashlib.sha256(bounded_root_bytes(
             '/etc/aegis-auto-terminal-source.json',4096,(0o600,))).hexdigest() ==
         edge['new_source_sha256'] and
         hashlib.sha256(bounded_root_bytes(
             '/var/lib/aegis-install/client/auto-guardian-install.json',
             1 << 20,(0o600,))).hexdigest() == edge['new_install_sha256'])
    return edge_sha


def _resume_completed_terminal_pointer(root, candidate, candidate_sha,
                                       package_sha, edge_sha, *, retried=False):
    """Credit only a live native inspected and sealed same-successor stage."""
    parent = control_directory()
    try:
        current = current_pointer(parent)
    finally:
        os.close(parent)
    if current is None:
        return None
    pointer = current[0]
    need(pointer['candidate_sha256'] == candidate_sha and
         pointer['boot_id'] == current_boot())
    # The R6 retry handles the exact finalized/same-seal crash cut. It does
    # not start another generation or use a Python receipt as grant.
    complete_terminal_seal_cut(candidate,pointer)
    try:
        observed = _rotation_report(call_output(
            [str(candidate),'auto-inspect-active-stage',pointer['stage']],
            maximum=139264,timeout=45),
            'aegis_auto_active_stage_inspection_v1')
    except (Refused, OSError, subprocess.SubprocessError):
        outcome = recover_current(candidate)
        need(outcome in ('recovered_stopped','recovered'))
        return 'terminal_migration_inverse_completed'
    need(type(observed.get('stage')) is dict and
         observed['stage'].get('path') == pointer['stage'] and
         type(observed.get('terminal')) is dict)
    unit = observed['terminal'].get('private_unit')
    need(type(unit) is str and
         re.fullmatch(r'aegis-auto@[0-9a-f]{64}\.service',unit))
    token = unit[len('aegis-auto@'):-len('.service')]
    control = Path('/var/lib/aegis-install/client')
    pending_path = control/('auto-terminal-registration-pending-'+token+'.json')
    complete_path = control/('auto-terminal-registration-complete-'+token+'.json')
    activation_path = control/('auto-terminal-activation-'+token+'.json')
    need(not pending_path.is_symlink() and not complete_path.is_symlink() and
         not activation_path.is_symlink())
    pending_exists = pending_path.exists()
    complete_exists = complete_path.exists()
    if not pending_exists and not complete_exists:
        # Finalized runtime with no registrar publication is an interrupted
        # Prepare. The native inverse owns its recovery; never run Stop again.
        outcome = recover_current(candidate)
        need(outcome in ('recovered_stopped','recovered'))
        return 'terminal_migration_inverse_completed'
    need(pending_exists, 'terminal_registration_complete_without_pending')
    if not complete_exists:
        need(not retried, 'terminal_registration_pending_retry_bound')
        outcome = recover_current(candidate)
        if outcome == 'terminal_active':
            return _resume_completed_terminal_pointer(
                root,candidate,candidate_sha,package_sha,edge_sha,retried=True)
        need(outcome in ('recovered_stopped','recovered'))
        return 'terminal_migration_inverse_completed'
    pending_raw = bounded_root_bytes(
        pending_path,
        4096,(0o600,))
    complete_raw = bounded_root_bytes(
        complete_path,
        4096,(0o600,))
    activation_raw = bounded_root_bytes(
        activation_path,
        4096,(0o600,))
    pending = strict_json(pending_raw)
    completion = strict_json(complete_raw)
    activation = strict_json(activation_raw)
    generation_raw = bounded_root_bytes(CONTROL/'generation.json',139264,(0o600,))
    generation = strict_json(generation_raw)
    need(type(generation) is dict and generation.get('schema') ==
         'aegis_auto_v2_generation_v1' and
         generation.get('report') == observed and
         pending == {'schema':'aegis_auto_terminal_registration_pending_v1',
                     'boot_id':pointer['boot_id'],'unit':unit,
                     'source_sha256':hashlib.sha256(bounded_root_bytes(
                         '/etc/aegis-auto-terminal-source.json',4096,
                         (0o600,))).hexdigest()} and
         completion.get('schema') ==
         'aegis_auto_terminal_registration_complete_v1' and
         completion.get('pending_sha256') == hashlib.sha256(pending_raw).hexdigest() and
         completion.get('activation_sha256') ==
         hashlib.sha256(activation_raw).hexdigest() and
         completion.get('active_generation_sha256') ==
         hashlib.sha256(generation_raw).hexdigest() and
         activation.get('schema')=='aegis_auto_terminal_activation_v1' and
         activation.get('unit')==unit and
         activation.get('boot_id')==pointer['boot_id'] and
         activation.get('active_generation_sha256')==
             completion['active_generation_sha256'] and
         _completed_terminal_migration(root,package_sha,candidate_sha) == edge_sha)
    parent = control_directory()
    try:
        after = current_pointer(parent)
        need(after is not None and after[0] == pointer)
    finally:
        os.close(parent)
    return 'terminal_active'


def _resume_completed_terminal_migration(root, package, candidate,
                                         candidate_sha, package_sha, progress,
                                         *, after_native_inverse=False):
    install_fd = guard_fd = None
    try:
        install_fd = _open_original_lock('/run/aegis-auto-install.lock',9)
        guard_fd = _open_original_lock(
            '/var/lib/aegis-install/client/device-guard.conf.lock',10)
        edge_sha = _completed_terminal_migration(root,package_sha,candidate_sha)
        need(edge_sha is not None)
        parent = control_directory()
        try:
            need(current_pointer(parent) is None)
        finally:
            os.close(parent)
        if after_native_inverse:
            try:
                current_sha = hashlib.sha256(bounded_root_bytes(
                    '/usr/local/bin/aegis-client',512 << 20,
                    (0o555,0o755))).hexdigest()
            except FileNotFoundError:
                current_sha = None
            if current_sha != candidate_sha or not _passive_package_complete(package):
                progress['phase'] = 'terminal_migration_inverse_reinstall'
                call_output(['/usr/bin/dpkg','--force-confold','--install',
                             str(package)],maximum=128 << 10,timeout=300,
                            pass_fds=(9,10))
        need(_passive_package_complete(package))
        _passive_package_source(root,candidate_sha)
        need(hashlib.sha256(bounded_root_bytes('/usr/local/bin/aegis-client',
             512 << 20,(0o555,0o755))).hexdigest() == candidate_sha)
        guardian = '/usr/local/lib/aegis/helpers/lib/aegis_auto_guardian.py'
        admitted = _rotation_report(call_output(
            ['/usr/bin/python3','-I','-B',guardian,
             'rotation-admitted-readback','9','10'],maximum=8192,
            timeout=45,pass_fds=(9,10)),
            'aegis_auto_guard_rotation_admitted_readback_v1')
        need(admitted.get('candidate_sha256') == candidate_sha and
             admitted.get('no_live_actors') is True)
        progress['phase'] = 'terminal_migration_completed_resume'
        call_output(['/bin/bash',str(root/'install.sh'),'client',
                     '--resume-v2-upgrade'],maximum=128 << 10,
                    timeout=300,pass_fds=(9,10))
        os.close(10);guard_fd = None
        os.close(9);install_fd = None
        return _resume_terminal_migration_install(root,candidate,None,progress)
    finally:
        if guard_fd is not None: os.close(guard_fd)
        if install_fd is not None: os.close(install_fd)


def _resume_terminal_migration(root, package, candidate, candidate_sha,
                               package_sha, requested_mode, progress):
    """Resume only the same retained successor after migration prepare.

    The pending leaf is a durable barrier. A different root, package, boot or
    private unit is refused; this path never repeats Stop or prepares another
    successor. Both original lock OFDs remain held through source admission.
    """
    pending_path = Path('/var/lib/aegis-install/client/terminal-migrations/pending.json')
    raw = bounded_root_bytes(pending_path, 4096, (0o600,))
    pending = strict_json(raw)
    need(raw == uninstall_journal.canonical(pending) + b'\n' and
         type(pending) is dict and set(pending) == {
         'schema','old_source_sha256','context_sha256','candidate_sha256',
         'package_sha256','release_root','unit','boot_id',
         'marker_roster_sha256','prior_head_sha256',
         'next_bundle_manifest_sha256','next_sums_sha256'} and
         pending['schema'] == 'aegis_auto_terminal_migration_pending_v1' and
         pending['release_root'] == str(root) and
         pending['candidate_sha256'] == candidate_sha and
         pending['package_sha256'] == package_sha and
         pending['boot_id'] == Path('/proc/sys/kernel/random/boot_id').read_text().strip() and
         type(pending['unit']) is str and
         re.fullmatch(r'aegis-auto@[0-9a-f]{64}\.service',pending['unit']) and
         all(type(pending[key]) is str and re.fullmatch(r'[0-9a-f]{64}',pending[key])
             for key in ('old_source_sha256','context_sha256',
                         'marker_roster_sha256',
                         'next_bundle_manifest_sha256','next_sums_sha256')) and
         (pending['prior_head_sha256'] is None or
          type(pending['prior_head_sha256']) is str and
          re.fullmatch(r'[0-9a-f]{64}',pending['prior_head_sha256'])) and
         requested_mode != 'socks-only')
    intent_sha = hashlib.sha256(raw).hexdigest()
    install_fd = guard_fd = None
    guardian = '/usr/local/lib/aegis/helpers/lib/aegis_auto_guardian.py'
    registrar = '/usr/local/lib/aegis/helpers/lib/aegis_auto_terminal_register.py'
    try:
        progress['phase'] = 'terminal_migration_reopen_locks'
        install_fd = _open_original_lock('/run/aegis-auto-install.lock', 9)
        guard_fd = _open_original_lock(
            '/var/lib/aegis-install/client/device-guard.conf.lock', 10)
        held = (9,10)
        need(bounded_root_bytes(pending_path,4096,(0o600,)) == raw)
        context_path = pending_path.parent/(
            'context-'+pending['context_sha256']+'.json')
        # A source-qualified old registrar must close an interrupted volatile
        # observer before the first dpkg effect. After B is installed, the
        # completed archive+absent RUN are mandatory and old code is not run.
        runtime_archive = pending_path.parent/(
            'observer-runtime-'+intent_sha+'.json')
        if (not context_path.exists() or not runtime_archive.exists() or
                Path('/run/aegis-auto-terminal').exists() or
                Path('/run/aegis-auto-terminal').is_symlink()):
            progress['phase'] = 'terminal_migration_complete_prepare'
            replay = strict_json(call_output(
                ['/usr/bin/python3','-I','-B',registrar,'migration-prepare',
                 pending['unit'],str(root),candidate_sha,package_sha,'9','10'],
                maximum=4096,timeout=120,pass_fds=held))
            need(replay == {'schema':'aegis_auto_terminal_migration_prepare_v1',
                            'status':'prepared','candidate_sha256':candidate_sha,
                            'intent_sha256':intent_sha})
        need(runtime_archive.exists() and not runtime_archive.is_symlink() and
             not Path('/run/aegis-auto-terminal').exists() and
             not Path('/run/aegis-auto-terminal').is_symlink())
        need(hashlib.sha256(bounded_root_bytes(context_path,256 << 10,
             (0o600,))).hexdigest() == pending['context_sha256'] and
             bounded_root_bytes(pending_path,4096,(0o600,)) == raw)
        _cold_archive_for_exact_successor(
            progress, 'terminal_cold_history_archive_replay',
            Path('/usr/local/bin/aegis-client'), root, intent_sha, 9, 10)
        progress['phase'] = 'terminal_migration_resume_package'
        if _passive_package_state(package) != 'installed':
            call_output(['/usr/bin/dpkg','--force-confold','--install',str(package)],
                        maximum=128 << 10, timeout=300, pass_fds=held)
        need(_passive_package_complete(package))
        _passive_package_source(root,candidate_sha)
        need(hashlib.sha256(bounded_root_bytes('/usr/local/bin/aegis-client',
             512 << 20,(0o555,0o755))).hexdigest() == candidate_sha)
        progress['phase'] = 'terminal_migration_resume_admission'
        try:
            admitted = _rotation_report(call_output(
                ['/usr/bin/python3','-I','-B',guardian,
                 'rotation-admitted-readback','9','10'], maximum=8192,
                timeout=45, pass_fds=held),
                'aegis_auto_guard_rotation_admitted_readback_v1')
        except (Refused, OSError, subprocess.SubprocessError):
            call_output(['/usr/bin/python3','-I','-B',guardian,
                         'admit-guarded-rotation','9','10'],
                        maximum=8192,timeout=45,pass_fds=held)
            admitted = _rotation_report(call_output(
                ['/usr/bin/python3','-I','-B',guardian,
                 'rotation-admitted-readback','9','10'], maximum=8192,
                timeout=45, pass_fds=held),
                'aegis_auto_guard_rotation_admitted_readback_v1')
        need(admitted.get('candidate_sha256') == candidate_sha and
             admitted.get('no_live_actors') is True)
        progress['phase'] = 'terminal_migration_resume_commit'
        migrated = strict_json(call_output(
            ['/usr/bin/python3','-I','-B',registrar,'migration-commit',
             pending['unit'],str(root),candidate_sha,package_sha,'9','10',intent_sha],
            maximum=4096,timeout=90,pass_fds=held))
        need(migrated.get('schema') == 'aegis_auto_terminal_migration_commit_v1' and
             migrated.get('status') == 'committed' and
             migrated.get('candidate_sha256') == candidate_sha and
             migrated.get('intent_sha256') == intent_sha)
        progress['phase'] = 'terminal_migration_resume_installer'
        call_output(['/bin/bash',str(root/'install.sh'),'client',
                     '--resume-v2-upgrade'],maximum=128 << 10,
                    timeout=300,pass_fds=held)
        os.close(10);guard_fd = None
        os.close(9);install_fd = None
        return _resume_terminal_migration_install(root,candidate,requested_mode,
                                                  progress)
    finally:
        if guard_fd is not None: os.close(guard_fd)
        if install_fd is not None: os.close(install_fd)


COLD_RECOVERY = Path('/var/lib/aegis-install/client/terminal-migrations/cold-recovery')
COLD_PROOF_FIELDS = frozenset({
    'schema','old_boot_id','current_boot_id','old_active_sha256',
    'old_stopped_sha256','successor_intent_sha256','old_install_sha256',
    'old_source_sha256','old_context_sha256','context_state',
    'cold_old_context_sha256','cold_context_state',
    'old_observer_archive_sha256','guardian_rotation_intent_sha256',
    'guardian_rotation_denied_sha256','guardian_rotation_retired_sha256',
    'retained_root','new_candidate_sha256','new_package_sha256',
    'package_state','installed_source_sha256','deny_policy_sha256',
    'guard30_sha256','selected_manager','manager31_sha256',
    'guardian31_sha256','migration_state','site_state',
    'site_readback_sha256','source_config_sha256',
    'observer_state','observer_source_sha256',
    'observer_ready_sha256','infrastructure_rows_sha256',
    'quiesce_state','quiesce_receipt_sha256','quiesce_monotonic_tick',
    'package_repair_receipt_sha256','package_repaired_tick',
    'infrastructure_qualified','infrastructure_quiescent',
    'client_actors_absent','jobs_absent',
    'cgroups_empty','stop_intent_absent','roster_sha256',
    'cold_intent_sha256',
})


def _cold_launcher_handoff(root, source_fd, handoff_fd, mode='ordinary'):
    """Refuse direct B Python entry without the native held-FD source handoff."""
    need(sys.platform.startswith('linux') and os.geteuid()==0 and
         source_fd==11 and handoff_fd==12 and source_fd!=handoff_fd)
    seals=fcntl.fcntl(handoff_fd,fcntl.F_GET_SEALS)
    required=(fcntl.F_SEAL_SEAL|fcntl.F_SEAL_SHRINK|
              fcntl.F_SEAL_GROW|fcntl.F_SEAL_WRITE)
    need(seals & required == required)
    memo=os.fstat(handoff_fd)
    need(stat.S_ISREG(memo.st_mode) and memo.st_uid==0 and
         0<memo.st_size<=4096)
    raw=os.pread(handoff_fd,4097,0)
    need(len(raw)==memo.st_size and raw.endswith(b'\n'))
    row=strict_json(raw)
    need(raw==(json.dumps(row,sort_keys=True,separators=(',',':'))+'\n').encode('ascii'))
    base_keys={
        'schema','boot_id','retained_root','candidate_sha256',
        'coordinator_sha256','successor_intent_sha256',
        'next_bundle_manifest_sha256','next_sums_sha256',
        'launcher_pid','launcher_start_tick'}
    rollover_keys=base_keys|{'mode','prior_intent_sha256','prior_boot_id',
                             'current_boot_id','original_intent_sha256',
                             'prior_pointer_state'}
    need(type(row) is dict and
        (mode=='ordinary' and set(row)==base_keys and
         row['schema']=='aegis_auto_cold_launcher_handoff_v1' or
         mode=='stale_rollover' and set(row)==rollover_keys and
         row['schema']=='aegis_auto_cold_launcher_handoff_v2' and
         row['mode']=='stale_rollover' and
         row['current_boot_id']==row['boot_id'] and
         type(row['prior_boot_id']) is str and
         row['prior_boot_id']!=row['current_boot_id'] and
         row['prior_pointer_state'] in
             ('absent','unsealed','sealed','sealed_incomplete') and
         all(type(row[key]) is str and
             re.fullmatch(r'[0-9a-f]{64}',row[key]) for key in
             ('prior_intent_sha256','original_intent_sha256'))) and
        row['boot_id']==current_boot() and row['retained_root']==str(root) and
        type(row['launcher_pid']) is int and
        row['launcher_pid']==os.getpid() and
        type(row['launcher_start_tick']) is int and
        row['launcher_start_tick']>0 and
        all(type(row[key]) is str and re.fullmatch(r'[0-9a-f]{64}',row[key])
            for key in ('candidate_sha256','coordinator_sha256',
                        'successor_intent_sha256',
                        'next_bundle_manifest_sha256','next_sums_sha256')))
    stat_raw=Path('/proc/self/stat').read_text(encoding='ascii')
    fields=stat_raw[stat_raw.rfind(')')+2:].split()
    need(len(fields)>19 and int(fields[19])==row['launcher_start_tick'])
    script=root/'scripts/lib/aegis_installer_auto_v2.py'
    before=os.fstat(source_fd)
    named=script.lstat()
    need(stat.S_ISREG(before.st_mode) and
         before.st_uid==before.st_gid==0 and before.st_nlink==1 and
         stat.S_IMODE(before.st_mode)==0o444 and
         0<before.st_size<=4 << 20 and
         Path(__file__).resolve()==script)
    body=os.pread(source_fd,4 << 20,0)
    after=os.fstat(source_fd)
    keys=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink',
          'st_size','st_mtime_ns','st_ctime_ns')
    need(len(body)==before.st_size and
         all(getattr(before,key)==getattr(after,key)==getattr(named,key)
             for key in keys) and
         hashlib.sha256(body).hexdigest()==row['coordinator_sha256'])
    need(hashlib.sha256(bounded_root_bytes(root/'SHA256SUMS',4 << 20,(0o444,)))
         .hexdigest()==row['next_sums_sha256'] and
         hashlib.sha256(bounded_root_bytes(root/'bundle.manifest.json',4 << 20,
                                            (0o444,)))
         .hexdigest()==row['next_bundle_manifest_sha256'] and
         hashlib.sha256(bounded_root_bytes(root/'bin/aegis-client',512 << 20,
                                            (0o555,)))
         .hexdigest()==row['candidate_sha256'])
    memo_after=os.fstat(handoff_fd)
    need(all(getattr(memo,key)==getattr(memo_after,key) for key in
             ('st_dev','st_ino','st_mode','st_uid','st_gid','st_size')) and
         os.pread(handoff_fd,4097,0)==raw)
    return row


def _cold_self_source(root):
    """Admit only the exact B coordinator retained in the signed bundle."""
    script = root/'scripts/lib/aegis_installer_auto_v2.py'
    need(Path(__file__).resolve() == script and not script.is_symlink())
    sums = {}
    raw = bounded_root_bytes(root/'SHA256SUMS',4 << 20,(0o444,))
    for line in raw.decode('ascii').splitlines():
        match = re.fullmatch(r'([0-9a-f]{64})  ([A-Za-z0-9_./@-]+)',line)
        need(match is not None and match[2] not in sums)
        sums[match[2]] = match[1]
    need(hashlib.sha256(bounded_root_bytes(script,4 << 20,(0o444,0o555)))
         .hexdigest() == sums['scripts/lib/aegis_installer_auto_v2.py'])


def _cold_retained_helper(root, relative):
    need(re.fullmatch(r'scripts/lib/[A-Za-z0-9_.-]{1,100}\.py',relative))
    rows = {}
    raw = bounded_root_bytes(root/'SHA256SUMS',4 << 20,(0o444,))
    for line in raw.decode('ascii').splitlines():
        match = re.fullmatch(r'([0-9a-f]{64})  ([A-Za-z0-9_./@-]+)',line)
        need(match is not None and match[2] not in rows)
        rows[match[2]] = match[1]
    need(relative in rows and
         hashlib.sha256(bounded_root_bytes(root/relative,4 << 20,(0o444,)))
         .hexdigest()==rows[relative])
    return root/relative

_COLD_STALE_FIELDS=frozenset({
    'schema','current_boot_id','prior_boot_id','original_intent_sha256',
    'prior_intent_sha256','retained_root','new_candidate_sha256',
    'next_bundle_manifest_sha256','next_sums_sha256',
    'prior_pointer_retirement_sha256','guard_shell_sha256',
    'guard30_sha256','deny_policy_sha256','client_actors_absent',
    'jobs_absent','cgroups_empty','stop_intent_absent','no_client_grant',
    'old_root','package_state','original_intent_state',
    'migration_state','site_state','manager31_state',
    'initial_denied_proof_sha256',
    'initial_infrastructure_rows_sha256'})

_COLD_STALE_GUARDIAN_FIELDS=frozenset({
    'schema','prior_intent_sha256','rotation_intent_sha256','boot_id',
    'selected_manager','guard30_sha256','manager31_sha256',
    'guardian31_sha256','state_sha256','policy_sha256',
    'manager_binding_sha256','observer_state','observer_source_sha256',
    'observer_ready_sha256','infrastructure_rows_sha256',
    'infrastructure_rows','infrastructure_quiescent',
    'infrastructure_qualified','quiesce_state','quiesce_receipt_sha256',
    'quiesce_monotonic_tick','package_repair_receipt_sha256',
    'package_repaired_tick','client_actors_absent','jobs_absent',
    'cgroups_empty','stop_intent_absent'})

def _cold_stale_guardian(root,install_fd,guard_fd,handoff,stale,
                         rotation_intent_sha):
    """Re-read the B-pinned guardian proof under the caller's held OFDs."""
    helper=_cold_retained_helper(root,'scripts/lib/aegis_auto_guardian.py')
    need(stale['prior_intent_sha256']==handoff['prior_intent_sha256'] and
         type(rotation_intent_sha) is str and
         re.fullmatch(r'[0-9a-f]{64}',rotation_intent_sha))
    helper_fd=os.open(helper,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        before=os.fstat(helper_fd)
        named=helper.lstat()
        keys=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink',
              'st_size','st_mtime_ns','st_ctime_ns')
        helper_raw=os.pread(helper_fd,4 << 20,0)
        need(stat.S_ISREG(before.st_mode) and
             before.st_uid==before.st_gid==0 and before.st_nlink==1 and
             stat.S_IMODE(before.st_mode)==0o444 and
             0<before.st_size<=4 << 20 and
             all(getattr(before,key)==getattr(named,key) for key in keys) and
             len(helper_raw)==before.st_size and
             hashlib.sha256(helper_raw).hexdigest()==
                 _cold_signed_row(root,'scripts/lib/aegis_auto_guardian.py'),
             'cold_stale_guardian_source_changed')
        argv=['/usr/bin/python3','-I','-B',
              '/proc/self/fd/'+str(helper_fd),
              'cold-stale-denied-readback',str(install_fd),str(guard_fd),
              str(root),handoff['prior_intent_sha256'],
              rotation_intent_sha,'--retained-source']
        row=strict_json(call_output(argv,maximum=128 << 10,timeout=90,
                                    pass_fds=(install_fd,guard_fd,helper_fd)))
        after=os.fstat(helper_fd)
        renamed=helper.lstat()
        need(all(getattr(before,key)==getattr(after,key)==
                 getattr(renamed,key) for key in keys),
             'cold_stale_guardian_generation_changed')
    finally:os.close(helper_fd)
    need(type(row) is dict and set(row)==_COLD_STALE_GUARDIAN_FIELDS and
         row['schema']=='aegis_auto_guard_cold_stale_denied_readback_v1' and
         row['boot_id']==handoff['current_boot_id']==current_boot() and
         row['prior_intent_sha256']==handoff['prior_intent_sha256'] and
         row['rotation_intent_sha256']==rotation_intent_sha and
         row['infrastructure_rows_sha256']==
             stale['initial_infrastructure_rows_sha256'] and
         row['policy_sha256']==stale['deny_policy_sha256'] and
         row['guard30_sha256']==stale['guard30_sha256'] and
         row['selected_manager'] in ('NetworkManager.service',
                                     'systemd-networkd.service') and
         row['infrastructure_qualified'] is True and
         all(row[key] is True for key in
             ('client_actors_absent','jobs_absent','cgroups_empty',
              'stop_intent_absent')) and
         type(row['infrastructure_rows']) is list and
         len(row['infrastructure_rows'])==6 and
         type(row['infrastructure_rows_sha256']) is str and
         re.fullmatch(r'[0-9a-f]{64}',row['infrastructure_rows_sha256']) and
         row['infrastructure_rows_sha256']==hashlib.sha256(
             (json.dumps(row['infrastructure_rows'],sort_keys=True,
                         separators=(',',':'))+'\n').encode('ascii')).hexdigest(),
         'cold_stale_guardian_readback_refused')
    need(hashlib.sha256((json.dumps(row,sort_keys=True,
            separators=(',',':'))+'\n').encode('ascii')).hexdigest()==
         stale['initial_denied_proof_sha256'],
         'cold_stale_guardian_native_digest_changed')
    return row


def _cold_attempt_intent_candidate(prior,handoff,stale,guardian,package_sha):
    """Derive a fresh full R9 intent from the authenticated prior chain."""
    need(type(prior) is dict and set(prior)==_COLD_INTENT_FIELDS and
         prior['schema']=='aegis_auto_terminal_cold_intent_v1' and
         prior['current_boot_id']==handoff['prior_boot_id'] and
         prior['successor_intent_sha256']==
             handoff['successor_intent_sha256'] and
         prior['new_candidate_sha256']==handoff['candidate_sha256'] and
         prior['new_package_sha256']==package_sha and
         prior['next_bundle_manifest_sha256']==
             handoff['next_bundle_manifest_sha256'] and
         prior['next_sums_sha256']==handoff['next_sums_sha256'] and
         prior['selected_manager']==guardian['selected_manager'] and
         guardian['policy_sha256']==stale['deny_policy_sha256'] and
         guardian['guard30_sha256']==stale['guard30_sha256'] and
         guardian['prior_intent_sha256']==handoff['prior_intent_sha256'] and
         guardian['rotation_intent_sha256']==
             prior['guardian_rotation_intent_sha256'],
         'cold_attempt_prior_chain_changed')
    current={**prior,
             'current_boot_id':handoff['current_boot_id'],
             'deny_policy_sha256':guardian['policy_sha256'],
             'guard30_sha256':guardian['guard30_sha256'],
             'manager31_sha256':guardian['manager31_sha256'],
             'initial_infrastructure_rows_sha256':
                 stale['initial_infrastructure_rows_sha256'],
             'initial_denied_proof_sha256':
                 stale['initial_denied_proof_sha256']}
    need(set(current)==_COLD_INTENT_FIELDS and
         current['old_boot_id']!=current['current_boot_id'] and
         current['current_boot_id']==current_boot(),
         'cold_attempt_intent_shape')
    raw=(json.dumps(current,sort_keys=True,separators=(',',':'))+'\n').encode('ascii')
    need(len(raw)<=8192,'cold_attempt_intent_oversize')
    return current,raw


def _cold_publish_attempt(handoff,intent_raw,barrier_sha):
    """Publish the exact currentboot intent before its immutable head."""
    intent=strict_json(intent_raw)
    need(type(intent) is dict and set(intent)==_COLD_INTENT_FIELDS and
         intent['schema']=='aegis_auto_terminal_cold_intent_v1' and
         intent['current_boot_id']==handoff['current_boot_id']==current_boot() and
         intent['retained_root']==handoff['retained_root'] and
         intent_raw==(json.dumps(intent,sort_keys=True,
                    separators=(',',':'))+'\n').encode('ascii'),
         'cold_attempt_intent_invalid')
    intent_sha=hashlib.sha256(intent_raw).hexdigest()
    parent=_cold_dir()
    try:
        if barrier_sha is None:
            need(hashlib.sha256(read_private(parent,'intent.json',8192))
                 .hexdigest()==handoff['original_intent_sha256'] and
                 not os.path.lexists(COLD_RECOVERY/'rollover-barrier.json'),
                 'cold_attempt_null_barrier_refused')
        else:
            need(type(barrier_sha) is str and
                 re.fullmatch(r'[0-9a-f]{64}',barrier_sha),
                 'cold_attempt_barrier_sha_invalid')
            observed=[]
            for leaf in ('rollover-barrier.json',
                         'rollover-barrier-consumed-'+barrier_sha+'.json'):
                try:observed.append(read_private(parent,leaf,8192))
                except FileNotFoundError:pass
            need(observed and len(set(observed))==1 and
                 hashlib.sha256(observed[0]).hexdigest()==barrier_sha,
                 'cold_attempt_barrier_changed')
        attempts=_cold_child_dir(parent,'attempts')
        try:
            name=handoff['current_boot_id']+'-'+handoff['prior_intent_sha256']
            stage_name='stage-'+name
            try:
                child=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|
                              os.O_CLOEXEC,dir_fd=attempts)
                final_exists=True
            except FileNotFoundError:
                need(not os.path.lexists(COLD_RECOVERY/'attempts'/stage_name),
                     'cold_attempt_unpublished_stage_requires_retirement')
                child=_cold_child_dir(attempts,stage_name)
                final_exists=False
            try:
                child_stat=os.fstat(child)
                parent_stat=os.fstat(attempts)
                need(stat.S_ISDIR(child_stat.st_mode) and
                     child_stat.st_uid==child_stat.st_gid==0 and
                     stat.S_IMODE(child_stat.st_mode)==0o700 and
                     child_stat.st_dev==parent_stat.st_dev,
                     'cold_attempt_child_untrusted')
                try:old=read_private(child,'intent.json',8192)
                except FileNotFoundError:
                    need(not final_exists,'cold_attempt_final_without_intent')
                    _cold_atomic_leaf(child,'intent.json',intent_raw)
                    old=read_private(child,'intent.json',8192)
                need(old==intent_raw and os.listdir(child)==['intent.json'],
                     'cold_attempt_intent_collision')
                os.fsync(child)
                if not final_exists:
                    libc=ctypes.CDLL(None,use_errno=True)
                    rename=libc.renameat2
                    rename.argtypes=(ctypes.c_int,ctypes.c_char_p,
                                     ctypes.c_int,ctypes.c_char_p,
                                     ctypes.c_uint)
                    rename.restype=ctypes.c_int
                    need(rename(attempts,stage_name.encode('ascii'),
                                attempts,name.encode('ascii'),1)==0,
                         'cold_attempt_publish_refused')
                    os.fsync(attempts)
                    named=os.stat(name,dir_fd=attempts,
                                  follow_symlinks=False)
                    held_child=os.fstat(child)
                    need((named.st_dev,named.st_ino)==
                         (held_child.st_dev,held_child.st_ino) and
                         not os.path.lexists(COLD_RECOVERY/'attempts'/
                                             stage_name),
                         'cold_attempt_publish_changed')
                else:
                    need(not os.path.lexists(COLD_RECOVERY/'attempts'/
                                             stage_name),
                         'cold_attempt_ambiguous_stage')
            finally:os.close(child)
        finally:os.close(attempts)
        head={'schema':'aegis_auto_terminal_cold_attempt_head_v1',
              'current_boot_id':handoff['current_boot_id'],
              'prior_boot_id':handoff['prior_boot_id'],
              'prior_intent_sha256':handoff['prior_intent_sha256'],
              'original_intent_sha256':handoff['original_intent_sha256'],
              'barrier_sha256':barrier_sha,
              'attempt_intent_sha256':intent_sha,
              'attempt_dir':str(COLD_RECOVERY/'attempts'/name)}
        head_raw=(json.dumps(head,sort_keys=True,separators=(',',':'))+'\n')
        head_raw=head_raw.encode('ascii')
        head_name='attempt-head-'+handoff['current_boot_id']+'-'+intent_sha+'.json'
        try:old=read_private(parent,head_name,8192)
        except FileNotFoundError:
            _cold_atomic_leaf(parent,head_name,head_raw)
            old=read_private(parent,head_name,8192)
        need(old==head_raw,'cold_attempt_head_collision')
        return {'intent_sha256':intent_sha,
                'head_sha256':hashlib.sha256(head_raw).hexdigest(),
                'attempt_dir':head['attempt_dir']}
    finally:os.close(parent)


def _cold_publish_barrier_record(handoff):
    """Publish the B-recognized sticky deny while retaining old lineage."""
    root=Path(handoff['retained_root'])
    shell=Path('/usr/local/lib/aegis/helpers/aegis-device-egress-guard.sh')
    shell_sha=_cold_signed_row(root,'scripts/aegis-device-egress-guard.sh')
    need(hashlib.sha256(bounded_root_bytes(shell,1 << 20,
          (0o500,0o555,0o755))).hexdigest()==shell_sha,
         'cold_rollover_shell_not_B')
    parent=_cold_dir()
    try:
        original_raw=None
        for leaf in ('intent.json','intent-consumed-'+
                     handoff['original_intent_sha256']+'.json'):
            try:raw=read_private(parent,leaf,8192)
            except FileNotFoundError:continue
            need(original_raw is None,'cold_rollover_original_ambiguous')
            original_raw=raw
        need(original_raw is not None and
             hashlib.sha256(original_raw).hexdigest()==
                 handoff['original_intent_sha256'],
             'cold_rollover_original_changed')
        original=strict_json(original_raw)
        need(type(original) is dict and set(original)==_COLD_INTENT_FIELDS and
             original['schema']=='aegis_auto_terminal_cold_intent_v1' and
             original['retained_root']==str(root) and
             original['new_candidate_sha256']==handoff['candidate_sha256'] and
             original['successor_intent_sha256']==
                 handoff['successor_intent_sha256'] and
             original['next_bundle_manifest_sha256']==
                 handoff['next_bundle_manifest_sha256'] and
             original['next_sums_sha256']==handoff['next_sums_sha256'],
             'cold_rollover_original_source_changed')
        barrier={'schema':'aegis_auto_terminal_cold_rollover_barrier_v1',
                 'original_intent_sha256':handoff['original_intent_sha256'],
                 'original_boot_id':original['current_boot_id'],
                 'retained_root':str(root),
                 'new_candidate_sha256':handoff['candidate_sha256'],
                 'next_bundle_manifest_sha256':
                     handoff['next_bundle_manifest_sha256'],
                 'next_sums_sha256':handoff['next_sums_sha256']}
        raw=(json.dumps(barrier,sort_keys=True,separators=(',',':'))+'\n')
        raw=raw.encode('ascii')
        try:existing=read_private(parent,'rollover-barrier.json',8192)
        except FileNotFoundError:
            _cold_atomic_leaf(parent,'rollover-barrier.json',raw)
            existing=read_private(parent,'rollover-barrier.json',8192)
        need(existing==raw,'cold_rollover_barrier_collision')
        barrier_sha=hashlib.sha256(raw).hexdigest()
        return barrier_sha
    finally:os.close(parent)


def _cold_publish_rollover_barrier(handoff,attempt_head_sha,
                                   attempt_intent_sha):
    """Bind the current attempt to a B shell barrier before B site mutation."""
    need(type(attempt_head_sha) is str and
         re.fullmatch(r'[0-9a-f]{64}',attempt_head_sha) and
         type(attempt_intent_sha) is str and
         re.fullmatch(r'[0-9a-f]{64}',attempt_intent_sha))
    barrier_sha=_cold_publish_barrier_record(handoff)
    parent=_cold_dir()
    try:
        head_raw=None
        for name in os.listdir(parent):
            if re.fullmatch(r'attempt-head-'+handoff['current_boot_id']+
                            r'-[0-9a-f]{64}\.json',name):
                need(head_raw is None,'cold_rollover_head_ambiguous')
                head_raw=read_private(parent,name,8192)
        need(head_raw is not None and
             hashlib.sha256(head_raw).hexdigest()==attempt_head_sha,
             'cold_rollover_head_changed')
        head=strict_json(head_raw)
        need(head['attempt_intent_sha256']==attempt_intent_sha and
             head['original_intent_sha256']==handoff['original_intent_sha256'] and
             head['current_boot_id']==handoff['current_boot_id'],
             'cold_rollover_head_wrong')
        if head['barrier_sha256'] is None:
            bound={'schema':'aegis_auto_terminal_cold_barrier_bound_v1',
                   'current_boot_id':handoff['current_boot_id'],
                   'attempt_head_sha256':attempt_head_sha,
                   'attempt_intent_sha256':attempt_intent_sha,
                   'barrier_sha256':barrier_sha,
                   'original_intent_sha256':handoff['original_intent_sha256']}
            bound_raw=(json.dumps(bound,sort_keys=True,
                        separators=(',',':'))+'\n').encode('ascii')
            name='barrier-bound-'+attempt_intent_sha+'.json'
            try:observed=read_private(parent,name,8192)
            except FileNotFoundError:
                _cold_atomic_leaf(parent,name,bound_raw)
                observed=read_private(parent,name,8192)
            need(observed==bound_raw,'cold_rollover_bound_collision')
        else:
            need(head['barrier_sha256']==barrier_sha,
                 'cold_rollover_head_barrier_changed')
        return barrier_sha
    finally:os.close(parent)

def _cold_signed_row(root, relative):
    need(type(relative) is str and
         re.fullmatch(r'[A-Za-z0-9_./@-]{1,160}',relative))
    rows={}
    raw=bounded_root_bytes(root/'SHA256SUMS',4 << 20,(0o444,))
    for line in raw.decode('ascii').splitlines():
        match=re.fullmatch(r'([0-9a-f]{64})  ([A-Za-z0-9_./@-]+)',line)
        need(match is not None and match[2] not in rows)
        rows[match[2]]=match[1]
    need(relative in rows)
    return rows[relative]

def _cold_stale_readback(candidate,root,install_fd,guard_fd,handoff,
                         retirement_sha):
    command=[str(candidate),'auto-verify-cold-stale-inherited',
             '--lock-fd',str(install_fd),'--guard-fd',str(guard_fd),
             '--retained-root',str(root),'--prior-intent-sha256',
             handoff['prior_intent_sha256']]
    row=strict_json(call_output(command,maximum=8192,timeout=90,
                                pass_fds=(install_fd,guard_fd)))
    need(type(row) is dict and set(row)==_COLD_STALE_FIELDS and
         row['schema']=='aegis_auto_v2_cold_stale_verification_v1' and
         row['current_boot_id']==current_boot() and
         row['current_boot_id']==handoff['current_boot_id'] and
         row['prior_boot_id']==handoff['prior_boot_id'] and
         row['original_intent_sha256']==handoff['original_intent_sha256'] and
         row['prior_intent_sha256']==handoff['prior_intent_sha256'] and
         row['retained_root']==str(root) and
         row['new_candidate_sha256']==handoff['candidate_sha256'] and
         row['next_bundle_manifest_sha256']==
             handoff['next_bundle_manifest_sha256'] and
         row['next_sums_sha256']==handoff['next_sums_sha256'] and
         row['prior_pointer_retirement_sha256']==retirement_sha and
         all(type(row[key]) is str and re.fullmatch(r'[0-9a-f]{64}',row[key])
             for key in ('initial_denied_proof_sha256',
                         'initial_infrastructure_rows_sha256')) and
         all(row[key] is True for key in ('client_actors_absent','jobs_absent',
             'cgroups_empty','stop_intent_absent','no_client_grant')) and
         type(row['old_root']) is str and re.fullmatch(
             r'/var/lib/aegis-auto/releases/[A-Za-z0-9-]{16,128}',
             row['old_root']) and
         row['package_state'] in ('old_exact','known_interrupted','new_exact') and
         row['original_intent_state'] in ('active','consumed') and
         row['migration_state'] in
             ('preparation_absent','pending_prefix','completed_edge') and
         row['site_state'] in
             ('a_exact','a_retiring_prefix','absent','b_prefix','b_complete') and
         row['manager31_state'] in ('a_exact','absent','b_exact') and
         all(type(row[key]) is str and re.fullmatch(r'[0-9a-f]{64}',row[key])
             for key in ('guard30_sha256','deny_policy_sha256')) and
         (row['guard_shell_sha256'] is None or
          type(row['guard_shell_sha256']) is str and
          re.fullmatch(r'[0-9a-f]{64}',row['guard_shell_sha256'])) and
         (row['original_intent_state']=='consumed' and
          row['package_state']=='new_exact' and
          row['guard_shell_sha256']==
              _cold_signed_row(root,'scripts/aegis-device-egress-guard.sh') or
          row['original_intent_state']=='active' and
          (row['package_state']=='new_exact' and
           row['guard_shell_sha256']==
               _cold_signed_row(root,'scripts/aegis-device-egress-guard.sh') or
           row['package_state'] in ('old_exact','known_interrupted') and
           (row['manager31_state']=='a_exact' or
            row['migration_state']=='pending_prefix'))))
    return row


def _cold_existing_attempt_head(handoff):
    """Use names only to select the stricter native replay proof path."""
    if not COLD_RECOVERY.exists() and not COLD_RECOVERY.is_symlink():
        return False
    parent=directory(COLD_RECOVERY,0o700)
    try:
        names=[name for name in os.listdir(parent) if name.startswith(
            'attempt-head-'+handoff['current_boot_id']+'-')]
        need(len(names)<=1 and all(re.fullmatch(
            r'attempt-head-'+handoff['current_boot_id']+
            r'-[0-9a-f]{64}\.json',name) for name in names),
            'cold_current_attempt_head_ambiguous')
        return bool(names)
    finally:os.close(parent)


def _cold_native_attempt(candidate,root,install_fd,guard_fd,handoff):
    row=strict_json(call_output(
        [str(candidate),'auto-verify-cold-attempt-inherited',
         '--lock-fd',str(install_fd),'--guard-fd',str(guard_fd),
         '--retained-root',str(root)],
        maximum=8192,timeout=90,pass_fds=(install_fd,guard_fd)))
    need(type(row) is dict and set(row)=={
         'schema','current_boot_id','original_intent_sha256',
         'prior_intent_sha256','barrier_sha256','attempt_intent_sha256',
         'attempt_head_sha256','attempt_dir',
         'prior_pointer_retirement_sha256','no_client_grant'} and
         row['schema']=='aegis_auto_v2_cold_attempt_resolution_v1' and
         row['current_boot_id']==handoff['current_boot_id']==current_boot() and
         row['original_intent_sha256']==handoff['original_intent_sha256'] and
         row['prior_intent_sha256']==handoff['prior_intent_sha256'] and
         row['attempt_dir']==str(COLD_RECOVERY/'attempts'/(
              handoff['current_boot_id']+'-'+handoff['prior_intent_sha256'])) and
         row['no_client_grant'] is True and
         all(type(row[key]) is str and re.fullmatch(r'[0-9a-f]{64}',row[key])
             for key in ('attempt_intent_sha256','attempt_head_sha256')),
         'cold_native_attempt_refused')
    return row

def _cold_retire_prior_pointer(candidate,root,handoff):
    """A fresh-lock native mutation; caller owns no Install/Guard OFD."""
    command=[str(candidate),'auto-retire-cold-prior-pointer',
             '--retained-root',str(root),'--prior-intent-sha256',
             handoff['prior_intent_sha256']]
    row=strict_json(call_output(command,maximum=4096,timeout=180))
    need(type(row) is dict and set(row)=={
         'schema','current_boot_id','prior_intent_sha256',
         'old_pointer_sha256','retirement_sha256','no_client_grant'} and
         row['schema']==
             'aegis_auto_v2_cold_prior_pointer_retirement_v1' and
         row['current_boot_id']==handoff['current_boot_id']==current_boot() and
         row['prior_intent_sha256']==handoff['prior_intent_sha256'] and
         row['no_client_grant'] is True and
         (row['old_pointer_sha256'] is None or
          type(row['old_pointer_sha256']) is str and
          re.fullmatch(r'[0-9a-f]{64}',row['old_pointer_sha256'])) and
         type(row['retirement_sha256']) is str and
         re.fullmatch(r'[0-9a-f]{64}',row['retirement_sha256']))
    return row


def _cold_retire_unpublished_stage(candidate,root,handoff):
    """Archive a failed unpublished attempt before reading stale authority."""
    command=[str(candidate),'auto-retire-cold-unpublished-stage',
             '--retained-root',str(root),'--prior-intent-sha256',
             handoff['prior_intent_sha256']]
    row=strict_json(call_output(command,maximum=4096,timeout=180))
    need(type(row) is dict and set(row)=={
         'schema','current_boot_id','prior_intent_sha256',
         'stage_name','stage_archive_sha256','no_client_grant'} and
         row['schema']==
             'aegis_auto_v2_cold_unpublished_stage_retirement_v1' and
         row['current_boot_id']==handoff['current_boot_id']==current_boot() and
         row['prior_intent_sha256']==handoff['prior_intent_sha256'] and
         row['no_client_grant'] is True and
         ((row['stage_name'] is None and
           row['stage_archive_sha256'] is None) or
          (row['stage_name']=='stage-'+handoff['current_boot_id']+'-'+
           handoff['prior_intent_sha256'] and
           type(row['stage_archive_sha256']) is str and
           re.fullmatch(r'[0-9a-f]{64}',row['stage_archive_sha256']))),
         'cold_unpublished_stage_retirement_refused')
    return row


def _cold_complete_orphan_head(candidate,root,handoff):
    """Complete only a native-authenticated immediate prior-boot intent cut."""
    command=[str(candidate),'auto-complete-cold-orphan-head',
             '--retained-root',str(root),'--prior-intent-sha256',
             handoff['prior_intent_sha256']]
    row=strict_json(call_output(command,maximum=4096,timeout=180))
    keys={'schema','current_boot_id','prior_intent_sha256',
          'old_orphan_intent_sha256','old_head_sha256','no_client_grant'}
    need(type(row) is dict and set(row)==keys and
         row['schema']=='aegis_auto_v2_cold_orphan_head_completion_v1' and
         row['current_boot_id']==handoff['current_boot_id']==current_boot() and
         row['prior_intent_sha256']==handoff['prior_intent_sha256'] and
         row['no_client_grant'] is True and
         ((row['old_orphan_intent_sha256'] is None and
           row['old_head_sha256'] is None) or
          (type(row['old_orphan_intent_sha256']) is str and
           re.fullmatch(r'[0-9a-f]{64}',row['old_orphan_intent_sha256']) and
           type(row['old_head_sha256']) is str and
           re.fullmatch(r'[0-9a-f]{64}',row['old_head_sha256']))),
         'cold_orphan_head_completion_refused')
    return row


_COLD_INTENT_FIELDS=frozenset({
    'schema','old_boot_id','current_boot_id','old_active_sha256',
    'old_stopped_sha256','successor_intent_sha256','old_install_sha256',
    'old_source_sha256','guardian_rotation_intent_sha256',
    'guardian_rotation_denied_sha256','guardian_rotation_retired_sha256',
    'retained_root','new_candidate_sha256','new_package_sha256',
    'selected_manager','manager31_sha256','guard30_sha256',
    'old_context_sha256','deny_policy_sha256',
    'initial_denied_proof_sha256','initial_infrastructure_rows_sha256',
    'next_bundle_manifest_sha256','next_sums_sha256'})

def _cold_prior_intent(root,handoff):
    """Read the unique named prior intent already authenticated by native."""
    parent=directory(COLD_RECOVERY,0o700)
    found=[]
    def consider(fd,name):
        try:raw=read_private(fd,name,8192)
        except FileNotFoundError:return
        if hashlib.sha256(raw).hexdigest()!=handoff['prior_intent_sha256']:
            return
        row=strict_json(raw)
        need(type(row) is dict and set(row)==_COLD_INTENT_FIELDS and
             row['schema']=='aegis_auto_terminal_cold_intent_v1' and
             row['current_boot_id']==handoff['prior_boot_id'] and
             row['retained_root']==str(root) and
             row['new_candidate_sha256']==handoff['candidate_sha256'] and
             row['successor_intent_sha256']==
                 handoff['successor_intent_sha256'] and
             row['next_bundle_manifest_sha256']==
                 handoff['next_bundle_manifest_sha256'] and
             row['next_sums_sha256']==handoff['next_sums_sha256'] and
             raw==(json.dumps(row,sort_keys=True,separators=(',',':'))+'\n')
                 .encode('ascii'),'cold_prior_intent_changed')
        found.append((row,raw))
    try:
        consider(parent,'intent.json')
        consider(parent,'intent-consumed-'+handoff['original_intent_sha256']+
                 '.json')
        try:
            attempts=os.open('attempts',os.O_RDONLY|os.O_DIRECTORY|
                             os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parent)
        except FileNotFoundError:
            need(not (COLD_RECOVERY/'attempts').is_symlink(),
                 'cold_attempts_symlink')
            attempts=None
        if attempts is not None:
            try:
                info=os.fstat(attempts)
                owner=os.fstat(parent)
                need(stat.S_ISDIR(info.st_mode) and
                     info.st_uid==info.st_gid==0 and
                     stat.S_IMODE(info.st_mode)==0o700 and
                     info.st_dev==owner.st_dev,
                     'cold_attempts_dir_untrusted')
                names=os.listdir(attempts)
                need(len(names)<=32 and all(re.fullmatch(
                    r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}-[0-9a-f]{64}',
                    name) for name in names),'cold_attempt_roster_invalid')
                for name in names:
                    child=os.open(name,os.O_RDONLY|os.O_DIRECTORY|
                                  os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=attempts)
                    try:
                        info=os.fstat(child)
                        need(stat.S_ISDIR(info.st_mode) and
                             info.st_uid==info.st_gid==0 and
                             stat.S_IMODE(info.st_mode)==0o700,
                             'cold_attempt_dir_untrusted')
                        consider(child,'intent.json')
                        consider(child,'intent-consumed-'+
                                 handoff['prior_intent_sha256']+'.json')
                    finally:os.close(child)
            finally:os.close(attempts)
    finally:os.close(parent)
    need(len(found)==1,'cold_prior_intent_ambiguous')
    return found[0]


def _cold_proof(root, candidate, candidate_sha, package_sha, handoff):
    proof = _rotation_report(call_output(
        [str(candidate),'auto-verify-cold-retired-successor','--lock-fd','9',
         '--guard-fd','10','--retained-root',str(root)],
        maximum=128 << 10,timeout=90,pass_fds=(9,10)),
        'aegis_auto_v2_cold_retired_successor_v2')
    need(set(proof) == COLD_PROOF_FIELDS and
         proof['retained_root'] == str(root) and
         proof['new_candidate_sha256'] == candidate_sha and
         proof['new_package_sha256'] == package_sha and
         proof['successor_intent_sha256'] ==
             handoff['successor_intent_sha256'] and
         proof['old_boot_id'] != proof['current_boot_id'] == current_boot() and
         proof['package_state'] in ('old_exact','new_exact','known_interrupted') and
         (proof['installed_source_sha256'] is None or
          type(proof['installed_source_sha256']) is str and
          re.fullmatch(r'[0-9a-f]{64}',proof['installed_source_sha256'])) and
         proof['selected_manager'] in ('NetworkManager.service',
                                        'systemd-networkd.service') and
         proof['migration_state'] in
             ('preparation_absent','pending_prefix','completed_edge') and
         proof['context_state'] in
             ('absent_not_prepared','missing_reconstructible','present_exact') and
         proof['cold_context_state'] in
             ('absent_not_prepared','missing_reconstructible','present_exact') and
         proof['site_state'] in
             ('a_exact','a_retiring_prefix','absent','b_prefix','b_complete') and
         proof['quiesce_state'] in ('pre','post') and
         type(proof['infrastructure_quiescent']) is bool and
         (proof['quiesce_state']=='pre') ==
             (proof['quiesce_receipt_sha256'] is None and
              proof['quiesce_monotonic_tick'] is None) and
         (proof['quiesce_state']!='post' or
              type(proof['quiesce_receipt_sha256']) is str and
              re.fullmatch(r'[0-9a-f]{64}',
                           proof['quiesce_receipt_sha256']) and
              type(proof['quiesce_monotonic_tick']) is int and
              proof['quiesce_monotonic_tick'] > 0) and
         (proof['quiesce_state']!='pre' or
              proof['package_state']=='old_exact' and
              (proof['site_state']=='a_exact' or
               proof['migration_state']=='pending_prefix' and
               proof['site_state'] in ('a_retiring_prefix','absent')) or
              proof['package_state']=='new_exact' and
              proof['migration_state'] in ('pending_prefix','completed_edge') and
              proof['site_state'] in ('b_prefix','b_complete') and
              proof['observer_state']=='absent' or
              proof['package_state']=='known_interrupted') and
         (proof['package_repair_receipt_sha256'] is None) ==
             (proof['package_repaired_tick'] is None) and
         (proof['package_repaired_tick'] is None or
              type(proof['package_repaired_tick']) is int and
              proof['package_repaired_tick']>
                  proof['quiesce_monotonic_tick']) and
         proof['observer_state'] in ('absent','b_ready') and
         all(proof[key] is True for key in
             ('infrastructure_qualified','client_actors_absent','jobs_absent',
              'cgroups_empty','stop_intent_absent')) and
         all(type(proof[key]) is str and re.fullmatch(r'[0-9a-f]{64}',proof[key])
             for key in ('old_active_sha256','old_stopped_sha256',
                         'successor_intent_sha256','old_install_sha256',
                         'old_source_sha256','guardian_rotation_intent_sha256',
                         'guardian_rotation_denied_sha256',
                         'guardian_rotation_retired_sha256',
                         'deny_policy_sha256','guard30_sha256',
                         'roster_sha256','site_readback_sha256',
                         'infrastructure_rows_sha256')) and
         all(proof[key] is None or type(proof[key]) is str and
             re.fullmatch(r'[0-9a-f]{64}',proof[key])
             for key in ('old_context_sha256','cold_old_context_sha256',
                         'old_observer_archive_sha256',
                         'manager31_sha256','guardian31_sha256',
                         'source_config_sha256',
                         'observer_source_sha256','observer_ready_sha256',
                         'cold_intent_sha256')) and
         (proof['quiesce_receipt_sha256'] is None or
          type(proof['quiesce_receipt_sha256']) is str and
          re.fullmatch(r'[0-9a-f]{64}',proof['quiesce_receipt_sha256'])) and
         (proof['package_repair_receipt_sha256'] is None or
          type(proof['package_repair_receipt_sha256']) is str and
          re.fullmatch(r'[0-9a-f]{64}',
                       proof['package_repair_receipt_sha256'])) and
         (proof['observer_state']=='absent') ==
             (proof['observer_source_sha256'] is None and
              proof['observer_ready_sha256'] is None))
    return proof


def _cold_complete_pending_context(root, candidate, candidate_sha,
                                   package_sha, first, handoff):
    need(first['migration_state']=='pending_prefix' and
         first['context_state']=='missing_reconstructible' and
         first['site_state']=='a_exact' and
         first['observer_state']=='absent' and
         first['package_state']=='old_exact')
    pending_path=Path('/var/lib/aegis-install/client/terminal-migrations/pending.json')
    raw=bounded_root_bytes(pending_path,4096,(0o600,))
    pending=strict_json(raw)
    need(type(pending) is dict and raw==(
         json.dumps(pending,sort_keys=True,separators=(',',':'))+'\n').encode('ascii') and
         pending.get('schema')=='aegis_auto_terminal_migration_pending_v1' and
         type(pending.get('unit')) is str and
         re.fullmatch(r'aegis-auto@[0-9a-f]{64}\.service',pending['unit']) and
         pending.get('candidate_sha256')==candidate_sha and
         pending.get('package_sha256')==package_sha and
         pending.get('release_root')==str(root) and
         pending.get('context_sha256')==first['old_context_sha256'])
    helper=_cold_retained_helper(root,'scripts/lib/aegis_auto_terminal_register.py')
    reply=strict_json(call_output(
        ['/usr/bin/python3','-I','-B',str(helper),'cold-complete-context',
         pending['unit'],str(root),candidate_sha,package_sha,'9','10'],
        maximum=4096,timeout=90,pass_fds=(9,10)))
    need(type(reply) is dict and set(reply)=={
         'schema','context_sha256','pending_sha256','current_boot_id',
         'status','no_client_grant'} and
         reply['schema']=='aegis_auto_terminal_cold_context_complete_v1' and
         reply['context_sha256']==first['old_context_sha256'] and
         reply['pending_sha256']==hashlib.sha256(raw).hexdigest() and
         reply['current_boot_id']==current_boot() and
         reply['status'] in ('published','already_present') and
         reply['no_client_grant'] is True)
    second=_cold_proof(root,candidate,candidate_sha,package_sha,handoff)
    need(second['context_state']=='present_exact' and
         second['old_context_sha256']==first['old_context_sha256'] and
         all(second[key]==first[key] for key in (
             'old_boot_id','old_active_sha256','old_stopped_sha256',
             'successor_intent_sha256','old_install_sha256',
             'old_source_sha256','new_candidate_sha256','new_package_sha256',
             'deny_policy_sha256','guard30_sha256','selected_manager')))
    return second


def _cold_full_flock(fdinfo, identity):
    """Require one whole-file exclusive flock on the exact inherited inode."""
    if len(fdinfo) > 4096:
        return False
    rows = [line.split() for line in fdinfo.splitlines()
            if line.startswith('lock:')]
    if len(rows) != 1:
        return False
    fields = rows[0]
    if (len(fields) != 9 or fields[0] != 'lock:' or
        re.fullmatch(r'[1-9][0-9]*:', fields[1]) is None or
        fields[2:5] != ['FLOCK','ADVISORY','WRITE'] or
        re.fullmatch(r'[0-9]+',fields[5]) is None or
        fields[7:] != ['0','EOF']):
        return False
    device = re.fullmatch(r'([0-9a-fA-F]+):([0-9a-fA-F]+):([0-9]+)',
                          fields[6])
    return (device is not None and
            int(device[1],16) == os.major(identity.st_dev) and
            int(device[2],16) == os.minor(identity.st_dev) and
            int(device[3]) == identity.st_ino)


def _cold_archive_package_source(old_root,new_root):
    """Pin this retained B child to old B's source and archived INSTALL."""
    script=old_root/'scripts/lib/aegis_installer_auto_v2.py'
    need(Path(__file__).resolve()==script,
         'cold_archive_package_wrong_source')
    expected=_cold_signed_row(old_root,'scripts/lib/aegis_installer_auto_v2.py')
    need(hashlib.sha256(bounded_root_bytes(script,1 << 20,(0o444,))).hexdigest()
         ==expected,'cold_archive_package_source_changed')
    client=Path('/var/lib/aegis-install/client')
    rotation=strict_json(bounded_root_bytes(
        client/'auto-guard-rotation-intent.json',1 << 20,(0o600,)))
    need(type(rotation) is dict and
         rotation.get('schema')=='aegis_auto_guard_rotation_intent_v1' and
         rotation.get('old_public_payload_root')==str(old_root) and
         type(rotation.get('successor')) is dict and
         rotation['successor'].get('next_public_payload_root')==str(new_root) and
         type(rotation.get('old_install_sha256')) is str and
         re.fullmatch(r'[0-9a-f]{64}',rotation['old_install_sha256']),
         'cold_archive_package_rotation_changed')
    archived=bounded_root_bytes(client/('auto-guardian-install-guarded-'+
        rotation['old_install_sha256']+'.json'),1 << 20,(0o600,))
    need(hashlib.sha256(archived).hexdigest()==rotation['old_install_sha256'],
         'cold_archive_package_old_install_changed')
    old_install=strict_json(archived)
    need(type(old_install) is dict and
         old_install.get('schema')=='aegis_auto_guardian_install_v1' and
         old_install.get('worker_sha256')==hashlib.sha256(
             bounded_root_bytes(old_root/'bin/aegis-client',
                                512 << 20,(0o555,))).hexdigest(),
         'cold_archive_package_old_install_changed')


def cold_package_readback(old_root_raw, new_root_raw, install_fd, guard_fd,
                          *, retained_source=False):
    """Closed A/B package facts; native proves old root and installed source."""
    need(sys.platform == 'linux' and os.geteuid() == 0 and
         type(install_fd) is int and type(guard_fd) is int and
         3 <= install_fd <= 1024 and 3 <= guard_fd <= 1024 and
         install_fd != guard_fd)
    old_root,new_root = absolute(old_root_raw),absolute(new_root_raw)
    need(old_root != new_root and
         old_root.parent == new_root.parent ==
             Path('/var/lib/aegis-auto/releases'))
    if retained_source:
        _cold_archive_package_source(old_root,new_root)
    else:
        _cold_self_source(new_root)
    old_package,old_package_sha = signed_client_package(old_root)
    new_package,new_package_sha = signed_client_package(new_root)
    # Inherited lock identities are checked again by the native parent. The
    # Python child also proves both FDs point at the fixed named inodes and
    # carry one exclusive flock before and after every filesystem read.
    for fd,path in ((install_fd,Path('/run/aegis-auto-install.lock')),
                    (guard_fd,Path('/var/lib/aegis-install/client/device-guard.conf.lock'))):
        held,named = os.fstat(fd),path.lstat()
        info = Path(f'/proc/self/fdinfo/{fd}').read_text(encoding='ascii')
        need(stat.S_ISREG(held.st_mode) and held.st_uid == held.st_gid == 0 and
             stat.S_IMODE(held.st_mode) == 0o600 and held.st_nlink == 1 and
             (held.st_dev,held.st_ino) == (named.st_dev,named.st_ino) and
             _cold_full_flock(info,held))
    def sums(root):
        result = {}
        raw = bounded_root_bytes(root/'SHA256SUMS',4 << 20,(0o444,))
        for line in raw.decode('ascii').splitlines():
            match = re.fullmatch(r'([0-9a-f]{64})  ([A-Za-z0-9_./@-]+)',line)
            need(match is not None and match[2] not in result)
            result[match[2]] = match[1]
        return result
    old_sums,new_sums = sums(old_root),sums(new_root)
    def optional_sha(path,maximum,modes):
        try: raw = bounded_root_bytes(path,maximum,modes)
        except FileNotFoundError:
            need(not path.is_symlink())
            return None,None
        return hashlib.sha256(raw).hexdigest(),stat.S_IMODE(path.lstat().st_mode)
    roster = []
    paths = [('helper/'+leaf,Path('/usr/local/lib/aegis/helpers')/leaf,
              ('packaging/systemd/system-shutdown/aegis-auto-terminal-hook'
               if leaf == 'lib/aegis-auto-terminal-hook' else 'scripts/'+leaf),
              ((0o644,0o755) if leaf == 'lib/root-state.sh' else
               (0o500,) if leaf.startswith('lib/aegis_auto_') or leaf in
               ('lib/aegis_installer_auto_v2.py','lib/aegis_initrd_policy.py',
                'lib/aegis_initrd_classic.py','lib/aegis-auto-terminal-hook') else (0o755,)))
             for leaf in FRESH_CLIENT_HELPERS]
    paths.extend(('unit/'+leaf,Path('/etc/systemd/system')/leaf,
                  'packaging/systemd/'+leaf,(0o644,))
                 for leaf in FRESH_CLIENT_UNITS)
    need(len(paths) == len({item[0] for item in paths}))
    relations = []
    for label,installed,relative,modes in paths:
        expected = []
        for root,rows in ((old_root,old_sums),(new_root,new_sums)):
            need(relative in rows)
            source_sha,source_mode = optional_sha(root/relative,4 << 20,
                                                   (0o444,0o555))
            need(source_sha == rows[relative] and
                 source_mode in (0o444,0o555))
            expected.append(source_sha)
        actual,mode = optional_sha(installed,4 << 20,modes)
        relation = ('absent' if actual is None else
                    'both' if actual == expected[0] == expected[1] else
                    'old' if actual == expected[0] else
                    'new' if actual == expected[1] else 'foreign')
        need(relation != 'foreign')
        roster.append({'path':label,'mode':mode,'sha256':actual,
                       'relation':relation})
        relations.append(relation)
    old_elf = hashlib.sha256(bounded_root_bytes(old_root/'bin/aegis-client',
                          512 << 20,(0o555,))).hexdigest()
    new_elf = hashlib.sha256(bounded_root_bytes(new_root/'bin/aegis-client',
                          512 << 20,(0o555,))).hexdigest()
    actual_elf,_ = optional_sha(Path('/usr/local/bin/aegis-client'),
                                512 << 20,(0o555,0o755))
    need(actual_elf in (None,old_elf,new_elf))
    installed_source,_ = optional_sha(
        Path('/var/lib/aegis-install/client/auto-guardian-install.json'),
        1 << 20,(0o600,))
    status = call_output(['/usr/bin/dpkg-query','-W',
        '--showformat=${Status}|${Version}|${Architecture}','aegis-client'],
        maximum=1024,timeout=10).decode('ascii').strip()
    fields = status.split('|')
    need(len(fields) == 3 and all(fields) and len(status) <= 256)
    def package_identity(path):
        return tuple(call_output(['/usr/bin/dpkg-deb','--field',str(path),key],
                     maximum=1024,timeout=10).decode('ascii').strip()
                     for key in ('Version','Architecture'))
    old_version,old_arch = package_identity(old_package)
    new_version,new_arch = package_identity(new_package)
    old_complete = (fields == ['install ok installed',old_version,old_arch] and
                    actual_elf == old_elf and
                    all(x in ('old','both') for x in relations))
    new_complete = (fields == ['install ok installed',new_version,new_arch] and
                    actual_elf == new_elf and
                    all(x in ('new','both') for x in relations))
    interrupted = (fields[0] in ('install ok unpacked','install ok half-configured',
                                 'install ok triggers-awaited',
                                 'install ok triggers-pending') and
                   fields[1:] == [new_version,new_arch])
    need(old_complete or new_complete or interrupted)
    state = ('new_exact' if new_complete else 'old_exact' if old_complete else
             'known_interrupted')
    roster_raw = (json.dumps(roster,sort_keys=True,separators=(',',':'))+'\n').encode()
    need(len(roster_raw) <= 64 << 10)
    result = {'schema':'aegis_auto_v2_cold_package_readback_v1',
              'boot_id':current_boot(),'old_root':str(old_root),
              'new_root':str(new_root),
              'old_package_sha256':old_package_sha,
              'new_package_sha256':new_package_sha,
              'dpkg_status':fields[0],'dpkg_version':fields[1],
              'dpkg_arch':fields[2],
              'installed_elf_sha256':actual_elf,
              'installed_source_sha256':installed_source,
              'roster_sha256':hashlib.sha256(roster_raw).hexdigest(),
              'roster':roster,'package_state':state}
    need(len(json.dumps(result,sort_keys=True,separators=(',',':'))) <= 64 << 10)
    for fd,path in ((install_fd,Path('/run/aegis-auto-install.lock')),
                    (guard_fd,Path('/var/lib/aegis-install/client/device-guard.conf.lock'))):
        held,named = os.fstat(fd),path.lstat()
        info = Path(f'/proc/self/fdinfo/{fd}').read_text(encoding='ascii')
        need(stat.S_ISREG(held.st_mode) and held.st_uid == held.st_gid == 0 and
             stat.S_IMODE(held.st_mode) == 0o600 and held.st_nlink == 1 and
             (held.st_dev,held.st_ino) == (named.st_dev,named.st_ino) and
             _cold_full_flock(info,held))
    return result


def _cold_dir():
    parent = COLD_RECOVERY.parent
    parent_fd = directory(parent,0o700)
    try:
        try:
            os.mkdir(COLD_RECOVERY.name,0o700,dir_fd=parent_fd)
            os.fsync(parent_fd)
        except FileExistsError:
            pass
        child = os.open(COLD_RECOVERY.name,os.O_RDONLY|os.O_DIRECTORY|
                        os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parent_fd)
        info = os.fstat(child)
        need(stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == 0 and
             stat.S_IMODE(info.st_mode) == 0o700 and
             info.st_dev == os.fstat(parent_fd).st_dev)
        return child
    finally:
        os.close(parent_fd)

def _cold_child_dir(parent_fd, name):
    """Create or reopen one exact private attempt directory on the same fs."""
    need(type(name) is str and re.fullmatch(r'[A-Za-z0-9_.-]{1,128}',name)
         and not name.startswith('.'))
    parent=os.fstat(parent_fd)
    need(stat.S_ISDIR(parent.st_mode) and parent.st_uid==parent.st_gid==0 and
         stat.S_IMODE(parent.st_mode)==0o700)
    try:
        os.mkdir(name,0o700,dir_fd=parent_fd)
        os.fsync(parent_fd)
    except FileExistsError:
        pass
    child=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,
                  dir_fd=parent_fd)
    named=os.stat(name,dir_fd=parent_fd,follow_symlinks=False)
    held=os.fstat(child)
    need(stat.S_ISDIR(held.st_mode) and held.st_uid==held.st_gid==0 and
         stat.S_IMODE(held.st_mode)==0o700 and held.st_dev==parent.st_dev and
         (held.st_dev,held.st_ino,held.st_mode,held.st_uid,held.st_gid)==
         (named.st_dev,named.st_ino,named.st_mode,named.st_uid,named.st_gid))
    return child


def _cold_open_phase_dir(path):
    """Open only the fixed original or a published current attempt directory."""
    if path==COLD_RECOVERY:
        return _cold_dir()
    need(type(path) is Path and path.parent==COLD_RECOVERY/'attempts' and
         re.fullmatch(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}-'
                      r'[0-9a-f]{64}',path.name),
         'cold_attempt_phase_path_invalid')
    parent=directory(COLD_RECOVERY/'attempts',0o700)
    try:
        child=os.open(path.name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|
                      os.O_CLOEXEC,dir_fd=parent)
        named=os.stat(path.name,dir_fd=parent,follow_symlinks=False)
        held=os.fstat(child)
        need(stat.S_ISDIR(held.st_mode) and held.st_uid==held.st_gid==0 and
             stat.S_IMODE(held.st_mode)==0o700 and
             held.st_dev==os.fstat(parent).st_dev and
             (held.st_dev,held.st_ino)==(named.st_dev,named.st_ino),
             'cold_attempt_phase_changed')
        return child
    finally:os.close(parent)

def _cold_atomic_leaf(parent_fd, name, raw):
    """No partial final JSON can survive an interrupted write or publish."""
    need(sys.platform.startswith('linux') and type(name) is str and
         re.fullmatch(r'[A-Za-z0-9_.-]{1,128}',name) and
         type(raw) is bytes and 0<len(raw)<=8192)
    fd=os.open('.',os.O_TMPFILE|os.O_WRONLY|os.O_CLOEXEC,0o600,
               dir_fd=parent_fd)
    try:
        offset=0
        while offset<len(raw):
            amount=os.write(fd,raw[offset:])
            need(amount>0)
            offset+=amount
        os.fsync(fd)
        libc=ctypes.CDLL(None,use_errno=True)
        linkat=libc.linkat
        linkat.argtypes=(ctypes.c_int,ctypes.c_char_p,ctypes.c_int,
                         ctypes.c_char_p,ctypes.c_int)
        linkat.restype=ctypes.c_int
        need(linkat(fd,b'',parent_fd,name.encode('ascii'),0x1000)==0)
        os.fsync(parent_fd)
        need(read_private(parent_fd,name,8192)==raw)
    finally:
        os.close(fd)


def _cold_phase(parent_fd, ordinal, row):
    need(type(ordinal) is int and 0 <= ordinal <= 5 and type(row) is dict)
    raw = (json.dumps(row,sort_keys=True,separators=(',',':'))+'\n').encode('ascii')
    need(len(raw) <= 8192)
    leaf = f'phase-{ordinal:02d}.json'
    try:
        current = read_private(parent_fd,leaf,8192)
    except FileNotFoundError:
        _cold_atomic_leaf(parent_fd,leaf,raw)
        current = read_private(parent_fd,leaf,8192)
    need(current == raw)
    return hashlib.sha256(raw).hexdigest()


def _cold_archive_noreplace(source_dir, source_name, target_dir, target_name):
    """Move one already authenticated inode without ever replacing a target."""
    libc=ctypes.CDLL(None,use_errno=True)
    rename=libc.renameat2
    rename.argtypes=(ctypes.c_int,ctypes.c_char_p,ctypes.c_int,
                     ctypes.c_char_p,ctypes.c_uint)
    rename.restype=ctypes.c_int
    need(rename(source_dir,source_name.encode('ascii'),
                target_dir,target_name.encode('ascii'),1)==0,
         'cold_archive_rename_refused')
    os.fsync(source_dir)
    os.fsync(target_dir)


def _cold_archive_native(old_client,root,pending_sha,install_fd,guard_fd):
    raw=call_output([str(old_client),'auto-verify-cold-history-archive-inherited',
                     '--lock-fd',str(install_fd),'--guard-fd',str(guard_fd),
                     '--retained-root',str(root),
                     '--ordinary-pending-sha256',pending_sha],
                    maximum=4 << 20,timeout=120,
                    pass_fds=(install_fd,guard_fd))
    row=strict_json(raw)
    need(type(row) is dict and set(row)=={
         'schema','current_boot_id','ordinary_pending_sha256',
         'old_source_sha256','member_manifest_sha256','deny_policy_sha256',
         'state','cold_root_present','no_client_grant'} and
         row['schema']=='aegis_auto_v2_cold_history_archive_verification_v1' and
         row['current_boot_id']==current_boot() and
         row['ordinary_pending_sha256']==pending_sha and
         row['state'] in ('source','archived_prefix','complete') and
         type(row['cold_root_present']) is bool and
         row['no_client_grant'] is True and
         all(type(row[key]) is str and
             re.fullmatch(r'[0-9a-f]{64}',row[key]) for key in
             ('old_source_sha256','member_manifest_sha256',
              'deny_policy_sha256')),
         'cold_archive_native_shape')
    return row


def _cold_archive_old_root_hint(incoming_root):
    """Read a bounded path hint; native binds it to the sealed stopped report."""
    path=Path('/var/lib/aegis-install/client/auto-guard-rotation-intent.json')
    raw=bounded_root_bytes(path,1 << 20,(0o600,))
    row=strict_json(raw)
    need(type(row) is dict and
         row.get('schema')=='aegis_auto_guard_rotation_intent_v1' and
         type(row.get('old_public_payload_root')) is str and
         type(row.get('successor')) is dict and
         row['successor'].get('next_public_payload_root')==str(incoming_root),
         'cold_archive_old_root_hint_invalid')
    old_root=absolute(row['old_public_payload_root'])
    need(old_root!=incoming_root and
         old_root.parent==incoming_root.parent==
         Path('/var/lib/aegis-auto/releases'),
         'cold_archive_old_root_hint_invalid')
    return old_root


def _cold_archive_child(root,pending_sha,install_fd,guard_fd):
    registrar=Path('/usr/local/lib/aegis/helpers/lib/aegis_auto_terminal_register.py')
    raw=call_output(['/usr/bin/python3','-I','-B',str(registrar),
                     'cold-history-archive-readback',str(install_fd),
                     str(guard_fd),pending_sha],maximum=4 << 20,timeout=90,
                    pass_fds=(install_fd,guard_fd))
    row=strict_json(raw)
    need(type(row) is dict and set(row)=={
         'schema','ordinary_pending_sha256','old_source_sha256',
         'cold_root','cold_root_present','members','member_manifest_sha256',
         'no_client_grant'} and
         row['schema']=='aegis_auto_terminal_cold_archive_roster_v1' and
         row['ordinary_pending_sha256']==pending_sha and
         row['cold_root']=='terminal-migrations/cold-recovery' and
         type(row['cold_root_present']) is bool and
         row['no_client_grant'] is True and
         type(row['members']) is list and len(row['members'])<=512 and
         type(row['member_manifest_sha256']) is str and
         re.fullmatch(r'[0-9a-f]{64}',row['member_manifest_sha256']) and
         hashlib.sha256((json.dumps(row['members'],sort_keys=True,
             separators=(',',':'))+'\n').encode('ascii')).hexdigest()==
             row['member_manifest_sha256'],
         'cold_archive_child_shape')
    return row


def _cold_history_archive_before_a2(old_client,root,pending_sha,
                                    install_fd,guard_fd):
    """Retain B-only cold evidence before the A2 package changes its parser."""
    need(type(pending_sha) is str and re.fullmatch(r'[0-9a-f]{64}',pending_sha),
         'cold_archive_pending_sha_invalid')
    old_root=_cold_archive_old_root_hint(root)
    old_client=old_root/'bin/aegis-client'
    first=_cold_archive_native(old_client,old_root,pending_sha,install_fd,guard_fd)
    if first['state']=='complete':
        return first['member_manifest_sha256']
    child=_cold_archive_child(old_root,pending_sha,install_fd,guard_fd)
    need(all(first[key]==child[key] for key in
             ('ordinary_pending_sha256','old_source_sha256',
              'member_manifest_sha256','cold_root_present')),
         'cold_archive_child_native_mismatch')
    if not child['members']:
        need(not child['cold_root_present'] and first['state']=='source',
             'cold_archive_empty_changed')
        return None
    client=Path('/var/lib/aegis-install/client')
    migration=client/'terminal-migrations'
    archive=client/('terminal-cold-history-'+pending_sha)
    need(not archive.is_symlink(),'cold_archive_foreign_target')
    if not archive.exists():
        archive.mkdir(mode=0o700)
        client_fd=directory(client,0o700)
        try:os.fsync(client_fd)
        finally:os.close(client_fd)
    archive_fd=directory(archive,0o700)
    try:
        intent={'schema':'aegis_auto_terminal_cold_archive_intent_v1',
                'boot_id':first['current_boot_id'],
                'ordinary_pending_sha256':pending_sha,
                'old_source_sha256':first['old_source_sha256'],
                'member_manifest_sha256':first['member_manifest_sha256'],
                'deny_policy_sha256':first['deny_policy_sha256'],
                'no_client_grant':True}
        intent_raw=(json.dumps(intent,sort_keys=True,
                    separators=(',',':'))+'\n').encode('ascii')
        try:before=read_private(archive_fd,'archive-intent.json',4096)
        except FileNotFoundError:
            _cold_atomic_leaf(archive_fd,'archive-intent.json',intent_raw)
            before=read_private(archive_fd,'archive-intent.json',4096)
        need(before==intent_raw,'cold_archive_intent_changed')
        if child['cold_root_present'] and os.path.lexists(migration/'cold-recovery'):
            migration_fd=directory(migration,0o700)
            try:
                need(not os.path.lexists(archive/'cold-recovery'),
                     'cold_archive_double_root')
                _cold_archive_noreplace(migration_fd,'cold-recovery',
                                       archive_fd,'cold-recovery')
            finally:os.close(migration_fd)
        preseal_names=sorted(row['path'] for row in child['members'] if
            re.fullmatch(r'auto-terminal-activation-preseal-[0-9a-f]{64}\.json',
                         row['path']))
        if preseal_names:
            if not os.path.lexists(archive/'preseal'):
                os.mkdir('preseal',0o700,dir_fd=archive_fd)
                os.fsync(archive_fd)
            preseal_fd=os.open('preseal',os.O_RDONLY|os.O_DIRECTORY|
                               os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=archive_fd)
            client_fd=directory(client,0o700)
            try:
                for name in preseal_names:
                    if os.path.lexists(client/name):
                        need(not os.path.lexists(archive/'preseal'/name),
                             'cold_archive_preseal_duplicate')
                        _cold_archive_noreplace(client_fd,name,preseal_fd,name)
            finally:
                os.close(client_fd)
                os.close(preseal_fd)
        second=_cold_archive_native(old_client,old_root,pending_sha,install_fd,guard_fd)
        need(second['state']=='archived_prefix' and
             all(second[key]==first[key] for key in
                 ('current_boot_id','ordinary_pending_sha256',
                  'old_source_sha256','member_manifest_sha256',
                  'deny_policy_sha256','cold_root_present')),
             'cold_archive_move_not_proven')
        complete={'schema':'aegis_auto_terminal_cold_archive_complete_v1',
                  'boot_id':first['current_boot_id'],
                  'ordinary_pending_sha256':pending_sha,
                  'archive_intent_sha256':hashlib.sha256(intent_raw).hexdigest(),
                  'old_source_sha256':first['old_source_sha256'],
                  'member_manifest_sha256':first['member_manifest_sha256'],
                  'no_client_grant':True}
        complete_raw=(json.dumps(complete,sort_keys=True,
                      separators=(',',':'))+'\n').encode('ascii')
        try:readback=read_private(archive_fd,'archive-complete.json',4096)
        except FileNotFoundError:
            _cold_atomic_leaf(archive_fd,'archive-complete.json',complete_raw)
            readback=read_private(archive_fd,'archive-complete.json',4096)
        need(readback==complete_raw,'cold_archive_complete_changed')
        final=_cold_archive_native(old_client,old_root,pending_sha,install_fd,guard_fd)
        need(final['state']=='complete' and
             final['member_manifest_sha256']==first['member_manifest_sha256'],
             'cold_archive_final_not_proven')
        return final['member_manifest_sha256']
    finally:os.close(archive_fd)


def _cold_archive_successor_profile(root):
    """Admit only an exact reviewed A2 or A3 archive consumer."""
    manifest=strict_json(bounded_root_bytes(
        root/'bundle.manifest.json',4 << 20,(0o444,)))
    need(type(manifest) is dict and
         manifest.get('schema')=='aegis_release_bundle_manifest_v2',
         'cold_archive_bundle_invalid')
    incoming=_cold_signed_row(root,
        'scripts/lib/aegis_auto_terminal_register.py')
    need(hashlib.sha256(bounded_root_bytes(
        root/'scripts/lib/aegis_auto_terminal_register.py',1 << 20,
        (0o444,))).hexdigest()==incoming,
        'cold_archive_incoming_register_changed')
    source = manifest.get('git_sha')
    if source in ('05b662114e6e892dca2c065b43bdb0778797f82c',
                  'c3d307626e531b9a75163ab760ed0d5fd55432de'):
        actual_elf=hashlib.sha256(bounded_root_bytes(
            root/'bin/aegis-client',512 << 20,(0o555,))).hexdigest()
        profile=_cold_archive_exact_pair(source,incoming,actual_elf)
        return profile
    client=Path('/var/lib/aegis-install/client')
    cold=client/'terminal-migrations/cold-recovery'
    preseal=tuple(name for name in os.listdir(client) if
                  name.startswith('auto-terminal-activation-preseal-'))
    if cold.exists() or cold.is_symlink() or preseal:
        installed=strict_json(bounded_root_bytes(
            client/'auto-guardian-install.json',1 << 20,(0o600,)))
        need(incoming==installed.get('terminal_register_sha256'),
             'cold_archive_new_source_requires_adapter')
    return 'same_source_or_no_cold_history'


def _cold_archive_exact_pair(source,incoming,elf_sha):
    need(incoming=='9f62abb8e65340fb5ff3ff85c75def5159b6b4b4c321d4c1ddd543597768e1cb',
         'cold_archive_successor_source_mismatch')
    pairs={
      '05b662114e6e892dca2c065b43bdb0778797f82c':
       ('a2','f3fc01961b8cdca54553c0027cc3828a77b3043ee9f84308b89ed58b88bbc674'),
      'c3d307626e531b9a75163ab760ed0d5fd55432de':
       ('a3','9d65862e9bcc96e0127e349cc54e2e2822425744ee0a6118b22284a2e9161f96'),
    }
    need(source in pairs,'cold_archive_successor_unknown')
    profile,expected=pairs[source]
    need(elf_sha==expected,'cold_archive_successor_elf_mismatch')
    return profile


def _cold_archive_for_exact_successor(progress, phase, old_client, root,
                                      pending_sha, install_fd, guard_fd):
    profile = _cold_archive_successor_profile(root)
    if profile not in ('a2', 'a3'):
        return None
    progress['phase'] = phase
    return _cold_history_archive_before_a2(
        old_client, root, pending_sha, install_fd, guard_fd)


_COLD_INFRASTRUCTURE_UNITS = (
    'aegis-auto-guardian.service',
    'aegis-auto-guardian-watchdog.service',
    'aegis-auto-witness-topology.service',
    'aegis-auto-capture-topology.service',
    'aegis-auto-trace-rollback-actor.service',
    'aegis-foreign-policy-monitor.service',
)


def _cold_stop_old_infrastructure():
    """Quiesce exact old user-space actors with neither owner lock held.

    The kernel egress guard and its deny policy remain active. The caller
    reacquires both locks and reruns native proof before recording the cut.
    """
    for unit in _COLD_INFRASTRUCTURE_UNITS:
        call_output(['/usr/bin/systemctl','stop',unit],maximum=1024,timeout=20)


def recover_terminal_rollover(public_root, source_fd, handoff_fd):
    """Start a fresh attempt only from the native source and deny handoff."""
    root = absolute(public_root)
    handoff=_cold_launcher_handoff(root,source_fd,handoff_fd,
                                   mode='stale_rollover')
    candidate=root/'bin/aegis-client'
    need(hashlib.sha256(bounded_root_bytes(candidate,512 << 20,(0o555,)))
         .hexdigest()==handoff['candidate_sha256'])
    _cold_self_source(root)
    _,package_sha=signed_client_package(root)
    if _cold_existing_attempt_head(handoff):
        phase_root=COLD_RECOVERY/'attempts'/(
            handoff['current_boot_id']+'-'+handoff['prior_intent_sha256'])
        if (phase_root/'phase-03.json').exists() or \
           (phase_root/'phase-03.json').is_symlink():
            # Phase 03 may already own a current-boot B stage. Run the
            # existing native active/stopped retry before any stale mutator.
            return recover_terminal_migration(
                root,source_fd,handoff_fd,phase_root=phase_root,
                handoff_override=handoff)
    _cold_retire_unpublished_stage(candidate,root,handoff)
    retired=_cold_retire_prior_pointer(candidate,root,handoff)
    _cold_complete_orphan_head(candidate,root,handoff)
    install_fd=guard_fd=None
    try:
        install_fd=_open_original_lock('/run/aegis-auto-install.lock',9)
        guard_fd=_open_original_lock(
            '/var/lib/aegis-install/client/device-guard.conf.lock',10)
        if _cold_existing_attempt_head(handoff):
            attempt=_cold_native_attempt(candidate,root,install_fd,guard_fd,
                                         handoff)
            phase_root=Path(attempt['attempt_dir'])
        else:
            stale=_cold_stale_readback(
                candidate,root,install_fd,guard_fd,handoff,
                retired['retirement_sha256'])
            prior,_=_cold_prior_intent(root,handoff)
            guardian=_cold_stale_guardian(
                root,install_fd,guard_fd,handoff,stale,
                prior['guardian_rotation_intent_sha256'])
            _current,intent_raw=_cold_attempt_intent_candidate(
                prior,handoff,stale,guardian,package_sha)
            barrier_sha=None
            if stale['original_intent_state']=='consumed':
                need(stale['package_state']=='new_exact' and
                     stale['guard_shell_sha256']==
                       _cold_signed_row(root,'scripts/aegis-device-egress-guard.sh'),
                     'cold_consumed_original_requires_B_shell')
                barrier_sha=_cold_publish_barrier_record(handoff)
            published=_cold_publish_attempt(handoff,intent_raw,barrier_sha)
            need(published['intent_sha256']==
                 hashlib.sha256(intent_raw).hexdigest(),
                 'cold_attempt_publication_changed')
            attempt=_cold_native_attempt(candidate,root,install_fd,guard_fd,
                                         handoff)
            need(attempt['attempt_intent_sha256']==published['intent_sha256'] and
                 attempt['attempt_head_sha256']==published['head_sha256'] and
                 attempt['attempt_dir']==published['attempt_dir'],
                 'cold_attempt_publication_not_native_bound')
            phase_root=Path(published['attempt_dir'])
    finally:
        if guard_fd is not None:os.close(guard_fd)
        if install_fd is not None:os.close(install_fd)
    return recover_terminal_migration(root,source_fd,handoff_fd,
             phase_root=phase_root,handoff_override=handoff)


def recover_terminal_migration(public_root, source_fd, handoff_fd, *,
                               phase_root=COLD_RECOVERY,
                               handoff_override=None):
    """Explicit console-only cold recovery, with no receipt-based route grant."""
    need(sys.platform == 'linux' and os.geteuid() == 0)
    root = absolute(public_root)
    handoff = (handoff_override if handoff_override is not None else
               _cold_launcher_handoff(root, source_fd, handoff_fd))
    need(phase_root==COLD_RECOVERY and handoff_override is None or
         phase_root!=COLD_RECOVERY and handoff_override is not None,
         'cold_phase_mode_mismatch')
    package,package_sha = signed_client_package(root)
    candidate = root/'bin/aegis-client'
    candidate_sha = hashlib.sha256(bounded_root_bytes(
        candidate,512 << 20,(0o555,))).hexdigest()
    need(candidate_sha == handoff['candidate_sha256'])
    _cold_self_source(root)
    if (phase_root/'phase-03.json').exists() or \
       (phase_root/'phase-03.json').is_symlink():
        need(not (phase_root/'phase-03.json').is_symlink())
        if (CONTROL/POINTER).exists() or (CONTROL/POINTER).is_symlink():
            need(not (CONTROL/POINTER).is_symlink(),
                 'cold_current_pointer_symlink')
            recovered=recover_current(candidate)
            need(recovered in ('terminal_active','recovered_stopped','recovered'),
                 'cold_current_recovery_unrecognized')
            if recovered=='terminal_active':
                installed=Path('/usr/local/bin/aegis-client')
                need(hashlib.sha256(bounded_root_bytes(installed,512 << 20,
                     (0o555,0o755))).hexdigest()==candidate_sha)
                phase_fd=_cold_open_phase_dir(phase_root)
                try:
                    intent_raw=read_private(phase_fd,'phase-00.json',8192)
                    intent_sha=hashlib.sha256(intent_raw).hexdigest()
                    active=_rotation_report(call_output(
                        [str(installed),'auto-verify-cold-active',
                         '--retained-root',str(root),
                         '--intent-sha256',intent_sha],
                        maximum=8192,timeout=180),
                        'aegis_auto_v2_cold_active_verification_v1')
                    need(set(active)=={
                         'schema','boot_id','stage',
                         'active_generation_sha256','intent_sha256',
                         'cold_prebind_sha256','candidate_sha256',
                         'private_unit',
                         'terminal_registration_complete_sha256'} and
                         active['boot_id']==current_boot() and
                         active['intent_sha256']==intent_sha and
                         active['candidate_sha256']==candidate_sha and
                         type(active['private_unit']) is str and
                         re.fullmatch(r'aegis-auto@[0-9a-f]{64}\.service',
                                      active['private_unit']),
                         'cold_active_replay_refused')
                    _cold_phase(phase_fd,5,{
                        'schema':'aegis_auto_terminal_cold_active_v1',
                        'intent_sha256':intent_sha,
                        'candidate_sha256':candidate_sha,
                        'current_boot_id':current_boot()})
                    return 'cold_active'
                finally:
                    os.close(phase_fd)
    install_fd = guard_fd = phase_fd = None
    try:
        install_fd = _open_original_lock('/run/aegis-auto-install.lock',9)
        guard_fd = _open_original_lock(
            '/var/lib/aegis-install/client/device-guard.conf.lock',10)
        first = _cold_proof(root,candidate,candidate_sha,package_sha,handoff)
        if first['context_state']=='missing_reconstructible':
            first=_cold_complete_pending_context(root,candidate,candidate_sha,
                                                 package_sha,first,handoff)
        need(first['context_state'] in ('absent_not_prepared','present_exact'))
        phase_fd = _cold_open_phase_dir(phase_root)
        try:
            existing_phase0=strict_json(read_private(phase_fd,'phase-00.json',8192))
        except FileNotFoundError:
            existing_phase0=None
        cold_context_sha = None
        if first['migration_state']=='preparation_absent':
            helper=_cold_retained_helper(
                root,'scripts/lib/aegis_auto_terminal_register.py')
            if first['cold_context_state']=='absent_not_prepared':
                candidate_context=strict_json(call_output(
                    ['/usr/bin/python3','-I','-B',str(helper),
                     'cold-old-context-candidate',str(root),'9','10'],
                    maximum=4096,timeout=90,pass_fds=(9,10)))
                need(type(candidate_context) is dict and
                     set(candidate_context)=={
                         'schema','context_sha256','successor_intent_sha256',
                         'current_boot_id','no_client_grant'} and
                     candidate_context['schema']==
                         'aegis_auto_terminal_cold_old_context_candidate_v1' and
                     candidate_context['successor_intent_sha256']==
                         first['successor_intent_sha256'] and
                     candidate_context['current_boot_id']==current_boot() and
                     candidate_context['no_client_grant'] is True and
                     type(candidate_context['context_sha256']) is str and
                     re.fullmatch(r'[0-9a-f]{64}',
                                  candidate_context['context_sha256']))
                cold_context_sha=candidate_context['context_sha256']
            else:
                need(first['cold_context_state'] in
                     ('missing_reconstructible','present_exact') and
                     type(first['cold_old_context_sha256']) is str and
                     re.fullmatch(r'[0-9a-f]{64}',
                                  first['cold_old_context_sha256']))
                cold_context_sha=first['cold_old_context_sha256']
        else:
            need(first['cold_context_state']=='absent_not_prepared' and
                 first['cold_old_context_sha256'] is None)
        immutable = {key:first[key] for key in (
            'old_boot_id','current_boot_id','old_active_sha256',
            'old_stopped_sha256','successor_intent_sha256',
            'old_install_sha256','old_source_sha256',
            'guardian_rotation_intent_sha256',
            'guardian_rotation_denied_sha256',
            'guardian_rotation_retired_sha256','retained_root',
            'new_candidate_sha256','new_package_sha256','selected_manager',
            'manager31_sha256','guard30_sha256')}
        if existing_phase0 is not None:
            need(type(existing_phase0) is dict and
                 type(existing_phase0.get('manager31_sha256')) in (str,type(None)))
            immutable['manager31_sha256']=existing_phase0['manager31_sha256']
        initial_proof_raw = (json.dumps(first,sort_keys=True,
            separators=(',',':'))+'\n').encode('ascii')
        base_intent = {'schema':'aegis_auto_terminal_cold_intent_v1',
                       **immutable,
                       'next_bundle_manifest_sha256':
                           handoff['next_bundle_manifest_sha256'],
                       'next_sums_sha256':handoff['next_sums_sha256'],
                       'old_context_sha256':cold_context_sha,
                       'deny_policy_sha256':first['deny_policy_sha256']}
        try:
            intent_raw = read_private(phase_fd,'phase-00.json',8192)
            intent = strict_json(intent_raw)
            need(type(intent) is dict and
                 set(intent) == set(base_intent)|{
                     'initial_denied_proof_sha256',
                     'initial_infrastructure_rows_sha256'} and
                 all(intent[key] == value for key,value in base_intent.items()) and
                 type(intent['initial_denied_proof_sha256']) is str and
                 re.fullmatch(r'[0-9a-f]{64}',intent['initial_denied_proof_sha256']) and
                 type(intent['initial_infrastructure_rows_sha256']) is str and
                 re.fullmatch(r'[0-9a-f]{64}',
                              intent['initial_infrastructure_rows_sha256']) and
                 intent_raw == (json.dumps(intent,sort_keys=True,
                     separators=(',',':'))+'\n').encode('ascii'))
        except FileNotFoundError:
            intent = {**base_intent,
                      'initial_infrastructure_rows_sha256':
                          first['infrastructure_rows_sha256'],
                      'initial_denied_proof_sha256':hashlib.sha256(
                          initial_proof_raw).hexdigest()}
            _cold_phase(phase_fd,0,intent)
            intent_raw = read_private(phase_fd,'phase-00.json',8192)
        identity_sha = hashlib.sha256(intent_raw).hexdigest()
        try:
            published_intent = read_private(phase_fd,'intent.json',8192)
        except FileNotFoundError:
            consumed_name='intent-consumed-'+identity_sha+'.json'
            try:
                ready_raw=read_private(phase_fd,'transition-ready.json',4096)
            except FileNotFoundError:
                need(not os.path.lexists(phase_root/consumed_name),
                     'cold_consumed_without_transition_proof')
                atomic_exclusive_bytes(phase_fd,'intent.json',intent_raw,0o600)
                published_intent=read_private(phase_fd,'intent.json',8192)
            else:
                ready=strict_json(ready_raw)
                need(type(ready) is dict and set(ready)=={
                     'schema','current_boot_id','intent_sha256',
                     'cold_prebind_sha256','source_config_sha256',
                     'observer_ready_sha256','site_readback_sha256',
                     'deny_policy_sha256','consumed_intent_leaf',
                     'consumed_pending_leaf'} and
                     ready['schema']==
                         'aegis_auto_terminal_cold_transition_ready_v1' and
                     ready['current_boot_id']==current_boot() and
                     ready['intent_sha256']==identity_sha and
                     ready['consumed_intent_leaf']==consumed_name and
                     ready_raw==(json.dumps(ready,sort_keys=True,
                         separators=(',',':'))+'\n').encode('ascii'),
                     'cold_consumed_ready_changed')
                published_intent=read_private(phase_fd,consumed_name,8192)
        need(published_intent == intent_raw and
             hashlib.sha256(published_intent).hexdigest() == identity_sha)
        if (first['migration_state']=='preparation_absent' and
            first['cold_context_state'] != 'present_exact'):
            published_context=strict_json(call_output(
                ['/usr/bin/python3','-I','-B',str(helper),
                 'cold-old-context-publish',str(root),cold_context_sha,'9','10'],
                maximum=4096,timeout=90,pass_fds=(9,10)))
            need(type(published_context) is dict and
                 set(published_context)=={
                     'schema','context_sha256','current_boot_id',
                     'no_client_grant'} and
                 published_context['schema']==
                     'aegis_auto_terminal_cold_old_context_published_v1' and
                 published_context['context_sha256']==cold_context_sha and
                 published_context['current_boot_id']==current_boot() and
                 published_context['no_client_grant'] is True)
            first=_cold_proof(root,candidate,candidate_sha,package_sha,handoff)
        need(first['migration_state']!='preparation_absent' or
             first['cold_context_state']=='present_exact' and
             first['cold_old_context_sha256']==cold_context_sha)
        try:
            phase1_raw=read_private(phase_fd,'phase-01.json',8192)
        except FileNotFoundError:
            initial_site_ok=(
                first['package_state']=='old_exact' and
                (first['site_state']=='a_exact' or
                 first['migration_state']=='pending_prefix' and
                 first['site_state'] in ('a_retiring_prefix','absent')) and
                first['observer_state']=='absent' or
                first['package_state']=='new_exact' and
                first['migration_state'] in ('pending_prefix','completed_edge') and
                first['site_state'] in ('b_prefix','b_complete') and
                first['observer_state']=='absent' or
                first['package_state']=='known_interrupted' and
                (first['site_state'] in
                     ('a_exact','a_retiring_prefix','b_prefix') and
                 first['observer_state']=='absent' or
                 first['site_state']=='b_complete' and
                 first['observer_state']=='absent'))
            need(initial_site_ok and first['quiesce_state']=='pre' and
                 (first['infrastructure_rows_sha256']==
                      intent['initial_infrastructure_rows_sha256'] or
                  existing_phase0 is not None and
                  first['infrastructure_quiescent'] is True) and
                 first['deny_policy_sha256']==intent['deny_policy_sha256'])
            os.close(10);guard_fd=None
            os.close(9);install_fd=None
            _cold_stop_old_infrastructure()
            install_fd=_open_original_lock('/run/aegis-auto-install.lock',9)
            guard_fd=_open_original_lock(
                '/var/lib/aegis-install/client/device-guard.conf.lock',10)
            quiesced=_cold_proof(root,candidate,candidate_sha,package_sha,handoff)
            need(quiesced['quiesce_state']=='pre' and
                 quiesced['package_state']==first['package_state'] and
                 quiesced['deny_policy_sha256']==intent['deny_policy_sha256'] and
                 quiesced['infrastructure_quiescent'] is True and
                 quiesced['observer_state']==first['observer_state'] and
                 all(quiesced[key]==value for key,value in immutable.items()),
                 'cold_quiesce_not_proven')
            ticks=os.sysconf('SC_CLK_TCK')
            need(type(ticks) is int and 1<=ticks<=10000 and
                 hasattr(time,'CLOCK_BOOTTIME'),'cold_boot_clock_unavailable')
            cut=int(time.clock_gettime(time.CLOCK_BOOTTIME)*ticks)+1
            need(cut>0,'cold_quiesce_tick_invalid')
            phase1={'schema':'aegis_auto_terminal_cold_deny_v2',
                    'intent_sha256':identity_sha,
                    'deny_policy_sha256':quiesced['deny_policy_sha256'],
                    'pre_quiesce_infrastructure_sha256':
                        intent['initial_infrastructure_rows_sha256'],
                    'post_quiesce_infrastructure_sha256':
                        quiesced['infrastructure_rows_sha256'],
                    'quiesce_monotonic_tick':cut}
            _cold_phase(phase_fd,1,phase1)
            phase1_raw=read_private(phase_fd,'phase-01.json',8192)
        phase1=strict_json(phase1_raw)
        need(type(phase1) is dict and set(phase1)=={
             'schema','intent_sha256','deny_policy_sha256',
             'pre_quiesce_infrastructure_sha256',
             'post_quiesce_infrastructure_sha256','quiesce_monotonic_tick'} and
             phase1['schema']=='aegis_auto_terminal_cold_deny_v2' and
             phase1['intent_sha256']==identity_sha and
             phase1['deny_policy_sha256']==intent['deny_policy_sha256'] and
             phase1['pre_quiesce_infrastructure_sha256']==
                 intent['initial_infrastructure_rows_sha256'] and
             type(phase1['quiesce_monotonic_tick']) is int and
             phase1['quiesce_monotonic_tick']>0 and
             phase1_raw==(json.dumps(phase1,sort_keys=True,
                 separators=(',',':'))+'\n').encode('ascii'),
             'cold_quiesce_receipt_changed')
        first=_cold_proof(root,candidate,candidate_sha,package_sha,handoff)
        need(first['quiesce_state']=='post' and
             first['quiesce_receipt_sha256']==
                 hashlib.sha256(phase1_raw).hexdigest() and
             first['quiesce_monotonic_tick']==
                 phase1['quiesce_monotonic_tick'])
        if first['package_state'] != 'new_exact':
            call_output(['/usr/bin/dpkg','--force-confold','--install',str(package)],
                        maximum=128 << 10,timeout=300,pass_fds=(9,10))
        need(_passive_package_complete(package))
        _passive_package_source(root,candidate_sha)
        need(call_output(['/usr/bin/dpkg','--verify','aegis-client'],
                         maximum=4096,timeout=30) == b'')
        try:
            phase2_raw=read_private(phase_fd,'phase-02.json',8192)
        except FileNotFoundError:
            # An A process started during dpkg would have a post-quiesce
            # start tick but still hold A Python code. Stop the exact six
            # units again after B package readback and before the B cut.
            os.close(10);guard_fd=None
            os.close(9);install_fd=None
            _cold_stop_old_infrastructure()
            install_fd=_open_original_lock('/run/aegis-auto-install.lock',9)
            guard_fd=_open_original_lock(
                '/var/lib/aegis-install/client/device-guard.conf.lock',10)
            repaired=_cold_proof(root,candidate,candidate_sha,package_sha,handoff)
            need(repaired['package_state']=='new_exact' and
                 repaired['quiesce_state']=='post' and
                 repaired['package_repair_receipt_sha256'] is None and
                 repaired['infrastructure_quiescent'] is True and
                 repaired['infrastructure_rows_sha256']==
                     phase1['post_quiesce_infrastructure_sha256'] and
                 repaired['installed_source_sha256'] is not None and
                 all(repaired[key]==value for key,value in immutable.items()
                     if key!='manager31_sha256') and
                 repaired['deny_policy_sha256']==intent['deny_policy_sha256'],
                 'cold_package_repair_not_proven')
            ticks=os.sysconf('SC_CLK_TCK')
            need(type(ticks) is int and 1<=ticks<=10000 and
                 hasattr(time,'CLOCK_BOOTTIME'))
            package_cut=int(time.clock_gettime(time.CLOCK_BOOTTIME)*ticks)+1
            tick_deadline=time.monotonic()+1.0
            while package_cut<=phase1['quiesce_monotonic_tick']:
                need(time.monotonic()<tick_deadline,
                     'cold_package_cut_clock_stalled')
                time.sleep(0.01)
                package_cut=int(time.clock_gettime(time.CLOCK_BOOTTIME)*ticks)+1
            repaired_proof_sha=hashlib.sha256((json.dumps(repaired,
                sort_keys=True,separators=(',',':'))+'\n').encode('ascii')).hexdigest()
            repaired_sha=_cold_phase(phase_fd,2,{
                'schema':'aegis_auto_terminal_cold_package_repaired_v2',
                'intent_sha256':identity_sha,
                'proof_sha256':repaired_proof_sha,
                'package_repaired_tick':package_cut})
            phase2_raw=read_private(phase_fd,'phase-02.json',8192)
        repaired = _cold_proof(root,candidate,candidate_sha,package_sha,handoff)
        need(repaired['package_state'] == 'new_exact' and
             repaired['installed_source_sha256'] is not None and
             all(repaired[key] == value for key,value in immutable.items()
                 if key!='manager31_sha256') and
             repaired['deny_policy_sha256'] == first['deny_policy_sha256'])
        phase2=strict_json(phase2_raw)
        need(type(phase2) is dict and set(phase2)=={
             'schema','intent_sha256','proof_sha256','package_repaired_tick'} and
             phase2['schema']=='aegis_auto_terminal_cold_package_repaired_v2' and
             phase2['intent_sha256']==identity_sha and
             type(phase2['proof_sha256']) is str and
             re.fullmatch(r'[0-9a-f]{64}',phase2['proof_sha256']) and
             type(phase2['package_repaired_tick']) is int and
             phase2['package_repaired_tick']>phase1['quiesce_monotonic_tick'] and
             phase2_raw==(json.dumps(phase2,sort_keys=True,
                 separators=(',',':'))+'\n').encode('ascii') and
             repaired['package_repair_receipt_sha256']==
                 hashlib.sha256(phase2_raw).hexdigest() and
             repaired['package_repaired_tick']==phase2['package_repaired_tick'],
             'cold_phase02_changed')
        repaired_sha=hashlib.sha256(phase2_raw).hexdigest()
        if phase_root!=COLD_RECOVERY:
            # The B shell is now installed. Publish its durable deny barrier
            # and bind the immutable null-barrier head before B site/31 edits.
            attempt=strict_json(call_output(
                [str(candidate),'auto-verify-cold-attempt-inherited',
                 '--lock-fd','9','--guard-fd','10','--retained-root',str(root)],
                maximum=8192,timeout=90,pass_fds=(9,10)))
            need(attempt.get('schema')==
                     'aegis_auto_v2_cold_attempt_resolution_v1' and
                 attempt.get('attempt_dir')==str(phase_root) and
                 attempt.get('attempt_intent_sha256')==identity_sha and
                 attempt.get('no_client_grant') is True,
                 'cold_rollover_attempt_changed_after_package')
            _cold_publish_rollover_barrier(
                handoff,attempt['attempt_head_sha256'],identity_sha)
            rebound=strict_json(call_output(
                [str(candidate),'auto-verify-cold-attempt-inherited',
                 '--lock-fd','9','--guard-fd','10','--retained-root',str(root)],
                maximum=8192,timeout=90,pass_fds=(9,10)))
            need(rebound.get('schema')==
                     'aegis_auto_v2_cold_attempt_resolution_v1' and
                 rebound.get('attempt_intent_sha256')==identity_sha and
                 type(rebound.get('barrier_sha256')) is str and
                 re.fullmatch(r'[0-9a-f]{64}',rebound['barrier_sha256']) and
                 rebound.get('no_client_grant') is True,
                 'cold_rollover_barrier_not_reproven')
        os.close(10); guard_fd = None
        os.close(9); install_fd = None
        try:
            phase3_raw=read_private(phase_fd,'phase-03.json',8192)
            phase3_existing=True
        except FileNotFoundError:
            phase3_existing=False
            # The native mutator is source-bound and idempotent across its
            # own prebind-before-pointer-retirement crash prefix. A prebind
            # leaf alone never authorizes skipping that retirement.
            retired = _rotation_report(call_output(
                [str(candidate),'auto-retire-cold-successor',
                 '--retained-root',str(root),'--intent-sha256',identity_sha],
                 maximum=8192,timeout=210),
                 'aegis_auto_v2_cold_retired_successor_retirement_v1')
            need(retired.get('boot_id') == current_boot() and
                 retired.get('intent_sha256') == identity_sha and
                 retired.get('deny_policy_sha256') ==
                     repaired['deny_policy_sha256'] and
                 retired.get('no_client_grant') is True and
                 type(retired.get('cold_prebind_sha256')) is str and
                 re.fullmatch(r'[0-9a-f]{64}',retired['cold_prebind_sha256']))
            prebind_raw=read_private(phase_fd,'cold-denied-prebind.json',8192)
            need(hashlib.sha256(prebind_raw).hexdigest()==
                 retired['cold_prebind_sha256'])
        else:
            prebind_raw=read_private(phase_fd,'cold-denied-prebind.json',8192)
        prebind=_rotation_report(call_output(
            [str(candidate),'auto-verify-cold-prebind',
             '--retained-root',str(root),'--intent-sha256',identity_sha],
             maximum=8192,timeout=210),
             'aegis_auto_v2_cold_prebind_verification_v1')
        prebind_sha=hashlib.sha256(prebind_raw).hexdigest()
        need(prebind.get('boot_id')==current_boot() and
             prebind.get('intent_sha256')==identity_sha and
             prebind.get('cold_prebind_sha256')==prebind_sha and
             prebind.get('deny_policy_sha256')==repaired['deny_policy_sha256'] and
             prebind.get('no_client_grant') is True)
        phase3={'schema':'aegis_auto_terminal_cold_denied_prebind_v2',
                'package_repaired_sha256':repaired_sha,
                'cold_prebind_sha256':prebind_sha,
                'intent_sha256':identity_sha}
        if not phase3_existing:
            _cold_phase(phase_fd,3,phase3)
        else:
            need(phase3_raw==(json.dumps(phase3,sort_keys=True,
                 separators=(',',':'))+'\n').encode('ascii'),
                 'cold_phase03_changed')
        install_fd=_open_original_lock('/run/aegis-auto-install.lock',9)
        guard_fd=_open_original_lock(
            '/var/lib/aegis-install/client/device-guard.conf.lock',10)
        registrar=_cold_retained_helper(
            root,'scripts/lib/aegis_auto_terminal_register.py')
        configured=strict_json(call_output(
            ['/usr/bin/python3','-I','-B',str(registrar),'cold-configure',
             str(root),identity_sha,'9','10'],
            maximum=4096,timeout=480,pass_fds=(9,10)))
        need(type(configured) is dict and set(configured)=={
             'schema','current_boot_id','intent_sha256',
             'cold_prebind_sha256','source_config_sha256',
             'observer_ready_sha256','no_client_grant'} and
             configured['schema']=='aegis_auto_terminal_cold_configure_v1' and
             configured['current_boot_id']==current_boot() and
             configured['intent_sha256']==identity_sha and
             configured['cold_prebind_sha256']==prebind_sha and
             configured['no_client_grant'] is True)
        ready_phase={'schema':'aegis_auto_terminal_cold_site_ready_v1',
                     'intent_sha256':identity_sha,
                     'cold_prebind_sha256':prebind_sha,
                     'source_config_sha256':configured['source_config_sha256'],
                     'observer_ready_sha256':configured['observer_ready_sha256']}
        _cold_phase(phase_fd,4,ready_phase)
        os.close(10);guard_fd=None
        os.close(9);install_fd=None
        # systemd starts the transition unit only after both original OFDs
        # have been released. That unit reacquires 9->10 and independently
        # verifies the cold proof before permitting normal manager bootstrap.
        call_output(['/usr/bin/systemctl','start',
                     'aegis-auto-terminal-transition.service'],timeout=150)
        result = cold_boot_current(root,candidate,candidate_sha,identity_sha,
                                   phase_root=phase_root)
        _cold_phase(phase_fd,5,{
            'schema':'aegis_auto_terminal_cold_active_v1',
            'intent_sha256':identity_sha,
            'candidate_sha256':candidate_sha,
            'current_boot_id':current_boot()})
        return result
    finally:
        if phase_fd is not None: os.close(phase_fd)
        if guard_fd is not None: os.close(guard_fd)
        if install_fd is not None: os.close(install_fd)


def cold_boot_current(root,candidate,candidate_sha,intent_sha,*,
                      phase_root=COLD_RECOVERY):
    """The native prebind boundary owns the current-boot stage authority."""
    installed = Path('/usr/local/bin/aegis-client')
    need(hashlib.sha256(bounded_root_bytes(installed,512 << 20,
         (0o555,0o755))).hexdigest() == candidate_sha)
    raw = call_output([str(installed),'auto-begin-cold-first-arm',
                       '--retained-root',str(root)],maximum=8192,timeout=420)
    proof = strict_json(raw)
    need(type(proof) is dict and set(proof) == {
         'schema','new_boot_id','old_boot_id','candidate_sha256',
         'public_payload_root','candidate_binary','installer_sha256',
         'cold_prebind_sha256','current_boot_id'} and
         proof['schema'] == 'aegis_auto_v2_cold_first_arm_verification_v1' and
         proof['current_boot_id'] == proof['new_boot_id'] == current_boot() and
         proof['old_boot_id'] != current_boot() and
         proof['candidate_sha256'] == candidate_sha and
         proof['public_payload_root'] == str(root) and
         proof['candidate_binary'] == str(candidate) and
         type(proof['cold_prebind_sha256']) is str and
         re.fullmatch(r'[0-9a-f]{64}',proof['cold_prebind_sha256']) and
         hashlib.sha256(bounded_root_bytes(root/'install.sh',8 << 20,
                          (0o555,0o755))).hexdigest() == proof['installer_sha256'])
    phase_fd = _cold_open_phase_dir(phase_root)
    try:
        intent = strict_json(read_private(phase_fd,'phase-00.json',8192))
        need(intent.get('current_boot_id') == current_boot() and
             intent.get('retained_root') == str(root) and
             hashlib.sha256((json.dumps(intent,sort_keys=True,
                  separators=(',',':'))+'\n').encode()).hexdigest() == intent_sha)
    finally:
        os.close(phase_fd)
    args = parser().parse_args([
        'install','--config-root','/etc/aegis/client',
        '--state-dir','/var/lib/aegis-client',
        '--metadata-dir','/var/lib/aegis-install/auto-client',
        '--staging-parent','/run/aegis-installer-config-snapshots',
        '--public-payload-root',str(root),'--candidate-binary',str(candidate),
        '--installed-binary',str(installed),
        '--runtime-events',str(AUTO_RUNTIME_EVENTS),
        '--existing-choice','upgrade'])
    need(run(args))
    return 'cold_active'


def upgrade_package(public_root, incoming_deb=None, requested_mode=None):
    """Upgrade one stopped V2 generation with original install and guard OFDs."""
    progress = {"phase": "package_preflight", "worker": None,
                "worker_started": None}
    install_fd = guard_fd = None
    terminal_migration = None
    try:
        need(sys.platform == "linux" and os.geteuid() == 0)
        root = absolute(public_root)
        package, _package_sha = signed_client_package(root, incoming_deb)
        candidate = root / "bin/aegis-client"
        candidate_fd = held_root_file(candidate, 512 << 20, (0o555,))
        try:
            candidate_sha = bounded_digest(candidate_fd, 512 << 20)[1]
        finally:
            os.close(candidate_fd)
        old = "/usr/local/bin/aegis-client"
        terminal_paths = (Path('/etc/aegis-auto-terminal-source.json'),
                          Path('/etc/aegis-auto-terminal-store.json'),
                          Path('/usr/lib/systemd/system-shutdown/aegis-auto-terminal-hook'))
        terminal_present = [path.exists() or path.is_symlink()
                            for path in terminal_paths]
        need(requested_mode in (None, "socks-only"))
        _incoming_upgrade_coordinator(root)
        migration_pending = Path('/var/lib/aegis-install/client/terminal-migrations/pending.json')
        if migration_pending.exists() or migration_pending.is_symlink():
            return _resume_terminal_migration(root,package,candidate,candidate_sha,
                                              _package_sha,requested_mode,progress)
        need(not any(terminal_present) or all(terminal_present))
        if requested_mode is None:
            complete_edge = _completed_terminal_migration(
                root,_package_sha,candidate_sha)
            if complete_edge is not None:
                pointer_result = _resume_completed_terminal_pointer(
                    root,candidate,candidate_sha,_package_sha,complete_edge)
                if pointer_result == 'terminal_migration_inverse_completed':
                    return _resume_completed_terminal_migration(
                        root,package,candidate,candidate_sha,_package_sha,progress,
                        after_native_inverse=True)
                if pointer_result is not None:
                    return pointer_result
                return _resume_completed_terminal_migration(
                    root,package,candidate,candidate_sha,_package_sha,progress)
        if all(terminal_present):
            retired_result = _resume_retired_terminal_rotation(
                root,package,candidate,candidate_sha,_package_sha,
                requested_mode,progress)
            if retired_result is not None:
                return retired_result
        preinst_present = (CONTROL / "passive-package-preinst.json").exists()
        retirement_present = (CONTROL / PASSIVE_SUCCESSOR_INTENT).exists()
        advance_pending = (CONTROL / "generation-passive-advance.json").exists()
        need(not (CONTROL / "passive-package-preinst.json").is_symlink() and
             not (CONTROL / PASSIVE_SUCCESSOR_INTENT).is_symlink() and
             not (CONTROL / "generation-passive-advance.json").is_symlink())
        if advance_pending:
            progress["phase"] = "package_advance"
            resumed = strict_json(call_output(
                [old, "auto-advance-completed-passive-transition"],
                maximum=8192, timeout=120))
            need(resumed.get("schema") ==
                 "aegis_auto_v2_passive_transition_advance_v1" and
                 resumed.get("outcome") == "archived" and
                 not (CONTROL / "generation-passive-advance.json").exists() and
                 not (CONTROL / "passive-package-preinst.json").exists() and
                 not (CONTROL / PASSIVE_SUCCESSOR_INTENT).exists())
            preinst_present = retirement_present = False
        if preinst_present:
            prior_root = _passive_transition_locator()
            if prior_root == str(root):
                return _passive_continue(root, package, candidate, candidate_sha,
                                         requested_mode, progress)
            progress["phase"] = "package_advance"
            advanced = strict_json(call_output(
                [old, "auto-advance-completed-passive-transition"],
                maximum=8192, timeout=120))
            need(advanced.get("schema") ==
                 "aegis_auto_v2_passive_transition_advance_v1" and
                 advanced.get("outcome") == "archived" and
                 not (CONTROL / "passive-package-preinst.json").exists() and
                 not (CONTROL / PASSIVE_SUCCESSOR_INTENT).exists())
        if retirement_present and not preinst_present:
            progress["phase"] = "package_lock"
            install_fd = _open_original_lock("/run/aegis-auto-install.lock", 9)
            parent = _passive_control()
            try:
                intent = _passive_record(parent, PASSIVE_SUCCESSOR_INTENT)
                need(intent is not None)
            finally:
                os.close(parent)
            _ensure_passive_old_stopped_report(intent, 9)
            _authenticate_passive_retirement_before_stop(intent, 9)
            prior = _successor_report(call_output(
                [old, "verify-passive-retirement-intent", "--lock-fd", "9"],
                maximum=128 << 10, timeout=30, pass_fds=(9,)), root,
                candidate_sha)
            need(prior["stopped"]["stage"]["mode"] == "socks-only")
            progress["phase"] = "package_retire_passive"
            retire_passive_successor(9)
            retired = _rotation_report(call_output(
                [old, "verify-retired-passive-successor", "--lock-fd", "9"],
                maximum=128 << 10, timeout=30, pass_fds=(9,)),
                "aegis_auto_v2_retired_passive_successor_verification_v1")
            need(retired["successor"] == prior["successor"] and
                 retired["stopped"] == prior["stopped"])
            progress["phase"] = "package_unpack"
            call_output(["/usr/bin/dpkg", "--force-confold", "--install",
                         str(package)], maximum=128 << 10, timeout=300,
                        pass_fds=(9,))
            os.close(9)
            install_fd = None
            return _passive_continue(root, package, candidate, candidate_sha,
                                     requested_mode, progress)
        if _passive_package_state(package) == "installed":
            installed_sha = hashlib.sha256(bounded_root_bytes(
                old, 512 << 20, (0o555, 0o755))).hexdigest()
            if installed_sha == candidate_sha:
                if _current_mode_hint() == "socks-only":
                    _passive_package_source(root, candidate_sha)
                    return _passive_completed_active(root, candidate_sha,
                                                     advance=False)
        if requested_mode == "socks-only":
            observed = strict_json(call_output(
                [old, "auto-verify-current-socks"], maximum=4096,
                timeout=30))
            need(observed.get("schema") == "aegis_auto_v2_current_socks_active_v1")
        old_fd = held_root_file(old, 512 << 20, (0o555, 0o755))
        os.close(old_fd)
        old_guardian = "/usr/local/lib/aegis/helpers/lib/aegis_auto_guardian.py"
        new_guardian = old_guardian
        old_guard_shell = "/usr/local/lib/aegis/helpers/aegis-device-egress-guard.sh"
        progress["phase"] = "package_stop"
        need(stop_current(requested_mode) in ("stopped", "noop"))
        progress["phase"] = "package_successor"
        begin = _successor_report(call_output(
            [old, "profile", "auto-config", "begin-stopped-successor",
             "--candidate-binary", str(candidate), "--public-payload-root", str(root)],
            maximum=128 << 10, timeout=90), root, candidate_sha)
        progress["phase"] = "package_lock"
        install_fd = _open_original_lock("/run/aegis-auto-install.lock", 9)
        verified = _successor_report(call_output(
            [old, "verify-stopped-successor", "--lock-fd", "9"],
            maximum=128 << 10, timeout=30, pass_fds=(9,)), root, candidate_sha)
        need(verified == begin)
        passive = begin["stopped"]["stage"]["mode"] == "socks-only"
        if requested_mode == "socks-only":
            need(passive)
        if passive:
            # A qualified terminal site cannot silently become a SOCKS-only
            # package transition without a separate source-bound retirement.
            need(not any(terminal_present))
            progress["phase"] = "package_retire_passive"
            retire_passive_successor(9)
            progress["phase"] = "package_verify_passive"
            retired = _rotation_report(call_output(
                [old, "verify-retired-passive-successor", "--lock-fd", "9"],
                maximum=128 << 10, timeout=45, pass_fds=(9,)),
                "aegis_auto_v2_retired_passive_successor_verification_v1")
        else:
            progress["phase"] = "package_prepare_guard"
            prepared = _rotation_report(call_output(
                ["/usr/bin/python3", "-I", "-B", old_guardian,
                 "prepare-guard-rotation", "9", str(root), str(candidate)],
                maximum=128 << 10, timeout=45, pass_fds=(9,)),
                "aegis_auto_guard_rotation_intent_v1")
            need(prepared.get("successor") == begin["successor"])
            guard_fd = _open_original_lock(
                "/var/lib/aegis-install/client/device-guard.conf.lock", 10)
            environment = dict(os.environ, AEGIS_AUTO_HELD_GUARD_FD="10",
                               AEGIS_DEVICE_GUARD_STATE=
                               "/var/lib/aegis-install/client/device-guard.conf")
            progress["phase"] = "package_block_guard"
            need(call_output(["/bin/bash", old_guard_shell, "block-rotation"],
                             maximum=4096, timeout=90, pass_fds=(10,),
                             env=environment) == b"")
            progress["phase"] = "package_retire_guard"
            _rotation_report(call_output(
                ["/usr/bin/python3", "-I", "-B", old_guardian,
                 "retire-rotation-actors", "9", "10"],
                maximum=128 << 10, timeout=180, pass_fds=(9, 10)),
                "aegis_auto_guard_rotation_retired_v1")
            progress["phase"] = "package_verify_retired"
            retired = _rotation_report(call_output(
                [old, "verify-retired-successor", "--lock-fd", "9",
                 "--guard-fd", "10"], maximum=128 << 10, timeout=45,
                pass_fds=(9, 10)), "aegis_auto_v2_retired_successor_verification_v1")
        need(set(retired) == {"schema", "stopped", "successor", "retired"} and
             retired["stopped"] == begin["stopped"] and
             retired["successor"] == begin["successor"] and
             retired["retired"].get("no_live_actors") is True)
        if any(terminal_present):
            need(not passive and guard_fd is not None)
            terminal_unit = retired['stopped']['terminal']['private_unit']
            need(type(terminal_unit) is str and
                 re.fullmatch(r'aegis-auto@[0-9a-f]{64}\.service', terminal_unit))
            progress["phase"] = "terminal_migration_prepare"
            terminal_migration = strict_json(call_output(
                ["/usr/bin/python3", "-I", "-B",
                 "/usr/local/lib/aegis/helpers/lib/aegis_auto_terminal_register.py",
                 "migration-prepare", terminal_unit, str(root),
                 candidate_sha, _package_sha, "9", "10"],
                maximum=4096, timeout=120, pass_fds=(9, 10)))
            need(type(terminal_migration) is dict and set(terminal_migration) ==
                 {"schema", "status", "candidate_sha256", "intent_sha256"} and
                 terminal_migration["schema"] ==
                 "aegis_auto_terminal_migration_prepare_v1" and
                 terminal_migration["status"] == "prepared" and
                 terminal_migration["candidate_sha256"] == candidate_sha and
                 type(terminal_migration["intent_sha256"]) is str and
                 re.fullmatch(r"[0-9a-f]{64}", terminal_migration["intent_sha256"]))
            _cold_archive_for_exact_successor(
                progress, 'terminal_cold_history_archive',
                Path(old), root, terminal_migration['intent_sha256'], 9, 10)
        progress["phase"] = "package_unpack"
        # Preserve administrator-owned /etc/default/aegis-client. The new
        # package treats source-owned AUTO units as regular payload files;
        # preinst checks their authenticated old bytes before replacement.
        held = (9,) if passive else (9, 10)
        call_output(["/usr/bin/dpkg", "--force-confold", "--install", str(package)],
                    maximum=128 << 10, timeout=300, pass_fds=held)
        need(_passive_package_complete(package))
        if passive:
            os.close(9)
            install_fd = None
            return _passive_continue(root, package, candidate, candidate_sha,
                                     requested_mode, progress)
        progress["phase"] = "package_admit_guard"
        call_output(["/usr/bin/python3", "-I", "-B", new_guardian,
                     "admit-guarded-rotation", "9", "10"],
                    maximum=8192, timeout=45, pass_fds=held)
        admitted = _rotation_report(call_output(
            ["/usr/bin/python3", "-I", "-B", new_guardian,
             "rotation-admitted-readback", "9", "10"],
            maximum=8192, timeout=45, pass_fds=held),
            "aegis_auto_guard_rotation_admitted_readback_v1")
        need(admitted.get("no_live_actors") is True and
             admitted.get("candidate_sha256") == candidate_sha)
        if terminal_migration is not None:
            progress["phase"] = "terminal_migration_commit"
            migrated = strict_json(call_output(
                ["/usr/bin/python3", "-I", "-B",
                 "/usr/local/lib/aegis/helpers/lib/aegis_auto_terminal_register.py",
                 "migration-commit", terminal_unit, str(root),
                 candidate_sha, _package_sha, "9", "10",
                 terminal_migration["intent_sha256"]],
                maximum=4096, timeout=90, pass_fds=held))
            need(type(migrated) is dict and set(migrated) ==
                 {"schema", "status", "candidate_sha256", "intent_sha256",
                  "new_source_sha256"} and
                 migrated["schema"] == "aegis_auto_terminal_migration_commit_v1" and
                 migrated["status"] == "committed" and
                 migrated["candidate_sha256"] == candidate_sha and
                 migrated["intent_sha256"] == terminal_migration["intent_sha256"] and
                 type(migrated["new_source_sha256"]) is str and
                 re.fullmatch(r"[0-9a-f]{64}", migrated["new_source_sha256"]))
        progress["phase"] = "package_resume"
        call_output(["/bin/bash", str(root / "install.sh"), "client",
                     "--resume-v2-upgrade"], maximum=128 << 10,
                    timeout=300, pass_fds=held)
        # The child releases the shared guard OFD only after protected state
        # handoff. Closing it here never grants a substitute guard authority.
        if guard_fd is not None:
            os.close(10)
            guard_fd = None
        os.close(9)
        install_fd = None
        progress["phase"] = "package_install"
        install_args = ["/usr/bin/python3", "-I", "-B", new_guardian.replace(
            "aegis_auto_guardian.py", "aegis_installer_auto_v2.py"),
            "install", "--config-root", "/etc/aegis/client", "--state-dir",
            "/var/lib/aegis-client", "--metadata-dir", "/var/lib/aegis-install/auto-client",
            "--staging-parent", "/run/aegis-installer-config-snapshots",
            "--public-payload-root", str(root), "--candidate-binary", str(candidate),
            "--installed-binary", old, "--runtime-events",
            str(AUTO_RUNTIME_EVENTS),
            "--existing-choice", "upgrade"]
        if requested_mode is not None:
            install_args.extend(("--requested-mode", requested_mode))
        result = strict_json(call_output(
            install_args, maximum=8192,
            timeout=960))
        need(result == {"status": "terminal_active"})
        return "terminal_active"
    except Exception as error:
        try:
            record_failure(progress, error)
        except Exception:
            pass
        raise
    finally:
        if guard_fd is not None:
            os.close(guard_fd)
        if install_fd is not None:
            os.close(install_fd)


def recover_prepare_handoff(candidate_path, *, boot_intent_sha256=None):
    """Finish only an authenticated completed Prepare, including crash cuts.

    This publishes bookkeeping for typed rollback, never activation authority.
    Intent-only Prepare remains sticky. The lock is released before any Rust
    recovery command acquires its own original InstallLock.
    """
    install_fd = _open_original_lock("/run/aegis-auto-install.lock", 9)
    try:
        parent = control_directory()
        try:
            pointer = current_pointer(parent)
            records = []
            for leaf in (PREPARE_CURRENT, PREPARE_COMPLETED):
                try:
                    records.append(control_leaf(parent, leaf)[0])
                except FileNotFoundError:
                    records.append(None)
            intent_raw, complete_raw = records
            if complete_raw is None:
                need(intent_raw is None)
                return
            complete = strict_json(complete_raw)
            intent_sha = complete.get("intent_sha256") if type(complete) is dict else None
            need(type(intent_sha) is str and re.fullmatch(r"[0-9a-f]{64}", intent_sha))
            if intent_raw is None:
                # An archive can precede retirement only after current.json is
                # durable. Refuse an archive-only claim without that pointer.
                need(pointer is not None)
                intent_raw, _ = control_leaf(parent, "prepare-archive-" + intent_sha + ".json")
            need(hashlib.sha256(intent_raw).hexdigest() == intent_sha)
        finally:
            os.close(parent)
        intent = strict_json(intent_raw)
        need(type(intent) is dict)
        stage = absolute(intent.get("stage"))
        need(stage.parent == Path("/run/aegis-installer-config-snapshots") and
             intent.get("candidate_binary") == str(candidate_path))
        paths = {"candidate-binary": candidate_path,
                 "public-payload-root": absolute(intent.get("public_payload_root"))}
        handoff = admitted_prepare_handoff(stage, paths, (intent_raw, complete_raw))
        prepared = strict_json(intent_raw)
        is_boot = prepared["schema"] == "aegis_auto_v2_boot_prepare_handoff_v2"
        if pointer is None:
            need(is_boot == (boot_intent_sha256 is not None) and
                 (not is_boot or prepared["boot_intent_sha256"] == boot_intent_sha256))
        else:
            need(boot_intent_sha256 is None)
            if is_boot:
                need(pointer[0]["schema"] == "aegis_installer_auto_v2_boot_stage_v3")
                boot_pending_recovery_intent(parent, pointer[0], require_v3=True)
        candidate = held_root_file(candidate_path, 256 << 20, (0o555, 0o755))
        try:
            candidate_sha = file_sha(candidate)[1]
        finally:
            os.close(candidate)
        verify_handoff_candidate(complete_raw, candidate_sha)
        verify_passive_prepared_references(stage, paths["public-payload-root"])
        fresh_package_lock(install_fd)
        if pointer is None:
            record_stage(stage, candidate_sha, Path("/usr/local/bin/aegis-client"),
                         handoff, boot_intent_sha256)
        else:
            need(pointer[0]["stage"] == str(stage) and
                 pointer[0]["boot_id"] == current_boot() and
                 pointer[0]["candidate_sha256"] == candidate_sha)
        archive_prepare_handoff(handoff)
        fresh_package_lock(install_fd)
    finally:
        os.close(install_fd)



def recover_fresh_prepared(public_root):
    """Recover only a first packaged pre-Bind failure before passive abort.

    The incoming actor authenticates and changes Header under its own lock,
    then atomically archives the original pending pointer without copying it.
    The following abort must re-admit all terminal facts under a fresh lock.
    No snapshot here authorizes a Rust effect and no worker fallback is
    available if the command refuses or loses its response.
    """
    need(sys.platform == "linux" and os.geteuid() == 0)
    root = absolute(str(public_root))
    _incoming_upgrade_coordinator(root)
    signed_client_package(root)
    install_fd = _open_original_lock("/run/aegis-auto-install.lock", 9)
    try:
        fresh_package_lock(install_fd)
        if PASSIVE_ABORT_PENDING.exists() or PASSIVE_ABORT_PENDING.is_symlink():
            _abort_pending_plan()
            return "abort-readback-required"
        try:
            parent = control_directory()
        except FileNotFoundError:
            need(not CONTROL.exists() and not CONTROL.is_symlink())
            return "abort-readback-required"
        try:
            current = current_pointer(parent)
            if current is None:
                # This is not a terminal-state certificate. The existing
                # abort gate proves no-Prepare, exact archived rollback or a
                # completed abort; a stray stage still refuses there.
                return "abort-readback-required"
            pointer = current[0]
            need(pointer["boot_id"] == current_boot() and
                 type(pointer["previous_binary"]) is dict and
                 pointer["previous_binary"]["sha256"] == pointer["candidate_sha256"])
            intent = _passive_record(parent, PASSIVE_INTENT)
            _passive_intent_shape(intent)
            need(intent["fresh_origin"] == "packaged" and
                 intent["boot_id"] == pointer["boot_id"] and
                 intent["source"]["candidate_sha256"] == pointer["candidate_sha256"] and
                 _passive_identity(intent["source"]["public_payload_root"],
                                   "packaged") == intent["source"])
            _passive_installed_origin(intent["source"], install_fd)
        finally:
            os.close(parent)
        fresh_package_lock(install_fd)
    finally:
        os.close(install_fd)
    # The command acquires its own existing original lock. Passing fd9 here
    # would collide with that authority and is deliberately prohibited.
    need(call_output([str(root / "bin/aegis-client"), "auto-rollback-fresh-prebind",
                      pointer["stage"], "--public-payload-root", str(root)],
                     maximum=1024, timeout=120) == b"")
    return "recovered"


def complete_terminal_seal_cut(candidate_path, pointer):
    """Complete only the sealed, same-boot pending registration crash cut.

    This caller holds no InstallLock.  The native auto-seal command acquires
    the original lock and re-proves the live finalized stage and source before
    publishing the exact registration.  Python's reads select that narrow
    retry; they confer no activation or network authority.
    """
    generation_path = CONTROL / 'generation.json'
    try:
        generation_raw = bounded_root_bytes(generation_path, 139264, (0o600,))
    except FileNotFoundError:
        return False
    active = strict_json(generation_raw)
    need(type(active) is dict and active.get('schema') ==
         'aegis_auto_v2_generation_v1' and
         type(active.get('report')) is dict)
    report = active['report']
    stage = report.get('stage')
    terminal = report.get('terminal')
    need(type(stage) is dict and type(terminal) is dict)
    if stage.get('path') != pointer['stage']:
        return False
    if stage.get('mode') == 'socks-only':
        return False
    unit = terminal.get('private_unit')
    need(type(unit) is str and
         re.fullmatch(r'aegis-auto@[0-9a-f]{64}\.service', unit) and
         stage.get('phase') == 'finalized' and
         stage.get('mode') in ('wide-redirect-safe','full-wide-tun') and
         terminal.get('boot_id') == pointer['boot_id'] == current_boot())
    token = unit[len('aegis-auto@'):-len('.service')]
    control = Path('/var/lib/aegis-install/client')
    pending = control / ('auto-terminal-registration-pending-' + token + '.json')
    complete = control / ('auto-terminal-registration-complete-' + token + '.json')
    try:
        pending_raw = bounded_root_bytes(pending, 4096, (0o600,))
    except FileNotFoundError:
        return False
    need(not complete.is_symlink())
    source_raw = bounded_root_bytes(Path('/etc/aegis-auto-terminal-source.json'),
                                    4096, (0o600,))
    need(strict_json(pending_raw) == {
        'schema':'aegis_auto_terminal_registration_pending_v1',
        'boot_id':pointer['boot_id'], 'unit':unit,
        'source_sha256':hashlib.sha256(source_raw).hexdigest()})
    need(call_output([str(candidate_path), 'auto-seal-generation', pointer['stage']],
                     maximum=1024, timeout=120, diagnostic_stderr=True) == b'')
    completion = strict_json(bounded_root_bytes(complete, 4096, (0o600,)))
    need(type(completion) is dict and set(completion) == {
        'schema','pending_sha256','activation_sha256',
        'active_generation_sha256'} and
        completion['schema'] == 'aegis_auto_terminal_registration_complete_v1' and
        completion['pending_sha256'] == hashlib.sha256(pending_raw).hexdigest() and
        completion['active_generation_sha256'] == hashlib.sha256(generation_raw).hexdigest() and
        type(completion['activation_sha256']) is str and
        re.fullmatch(r'[0-9a-f]{64}', completion['activation_sha256']) and
        bounded_root_bytes(pending, 4096, (0o600,)) == pending_raw and
        bounded_root_bytes(generation_path, 139264, (0o600,)) == generation_raw)
    parent = control_directory()
    try:
        same = current_pointer(parent)
        need(same is not None and same[0] == pointer)
    finally:
        os.close(parent)
    descriptor = os.open(candidate_path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        need(file_sha(descriptor)[1] == pointer['candidate_sha256'])
    finally:
        os.close(descriptor)
    return True


def recover_current(candidate_path, *, expected_pointer=None):
    """Use the actual rollback worker, then its separate locked recovery gate."""
    need(sys.platform == "linux" and os.geteuid() == 0)
    candidate_path = absolute(candidate_path)
    if expected_pointer is not None:
        parent = control_directory()
        try:
            observed = current_pointer(parent)
            need(observed is not None and observed[1] == expected_pointer)
        finally:
            os.close(parent)
    recover_prepare_handoff(candidate_path)
    parent = control_directory()
    try:
        current = current_pointer(parent)
        need(current is not None)
        need(expected_pointer is None or current[1] == expected_pointer)
        pointer = current[0]
        need(pointer["boot_id"] == current_boot())
    finally:
        os.close(parent)
    candidate = os.open(candidate_path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info = os.fstat(candidate)
        need(stat.S_ISREG(info.st_mode) and info.st_uid == info.st_gid == 0 and
             info.st_nlink == 1 and stat.S_IMODE(info.st_mode) in (0o555, 0o755) and
             file_sha(candidate)[1] == pointer["candidate_sha256"])
    finally:
        os.close(candidate)
    if complete_terminal_seal_cut(candidate_path, pointer):
        return 'terminal_active'
    command = [str(candidate_path), "auto-recover-rolled-back", pointer["stage"]]
    unsealed_command = [str(candidate_path), "auto-recover-unsealed-finalized",
                        pointer["stage"]]
    try:
        need(call_output(unsealed_command, maximum=1024, timeout=120) == b"")
        return "recovered_stopped"
    except (Refused, OSError, ValueError, subprocess.SubprocessError):
        parent = control_directory()
        try:
            # A present recovery certificate forbids a rollback0 worker.
            # Only the same-lock Rust stopped recovery may retire it.
            need(not unsealed_recovery_present(parent))
        finally:
            os.close(parent)
    # An earlier rollback may already be terminal but the separate archive
    # handoff may have failed. The Rust command proves this state itself.
    try:
        need(call_output(command, maximum=1024, timeout=120) == b"")
        return "recovered"
    except (Refused, OSError, ValueError, subprocess.SubprocessError):
        pass
    worker = subprocess.Popen([str(candidate_path), "profile", "auto-config",
                               "worker", "--stage", pointer["stage"]],
                              stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                              stderr=subprocess.DEVNULL, close_fds=True)
    started = time.monotonic()
    try:
        response(fixed_lines(worker, MAX_REPLY, started + PHASE_TIMEOUT), "ready")
        worker_phase(worker, ["rollback", "--capture-started", "0"], started)
        worker.stdin.close()
        need(worker.wait(timeout=30) == 0)
    finally:
        if worker.poll() is None:
            worker.stdin.close()
            try:
                worker.wait(timeout=min(90.0, max(0.0, started + WORKER_TIMEOUT - time.monotonic())))
            except subprocess.TimeoutExpired:
                worker.kill()
                worker.wait(timeout=5)
        worker.stdout.close()
    need(call_output(command, maximum=1024, timeout=120) == b"")
    return "recovered"



def boot_pending_recovery_intent(parent, pointer, *, require_v3=False):
    """Read the exact boot transition; a v3 pointer also binds its Prepare."""
    need(type(pointer) is dict and
         type(pointer.get("boot_id")) is str and
         type(pointer.get("candidate_sha256")) is str)
    sealed_report = None
    try:
        raw, _ = control_leaf(parent, "generation-boot-successor-current.json", 8192)
    except FileNotFoundError:
        # Only a committed exact new seal can select an archived boot intent.
        need(require_v3 and type(pointer.get("boot_intent_sha256")) is str and
             re.fullmatch(r"[0-9a-f]{64}", pointer["boot_intent_sha256"]))
        history = os.open("generation-history", os.O_RDONLY | os.O_DIRECTORY |
                          os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
        try:
            info = os.fstat(history)
            need(stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == 0 and
                 stat.S_IMODE(info.st_mode) == 0o700)
            raw, _ = control_leaf(history,
                "boot-intent-" + pointer["boot_intent_sha256"] + ".json", 8192)
        finally:
            os.close(history)
        active_raw, _ = control_leaf(parent, "generation.json", 139264)
        active = strict_json(active_raw)
        need(type(active) is dict and
             active.get("schema") == "aegis_auto_v2_generation_v1" and
             active.get("predecessor_boot_intent_sha256") ==
                 pointer["boot_intent_sha256"] and
             type(active.get("report")) is dict and
             type(active["report"].get("stage")) is dict and
             type(active["report"].get("terminal")) is dict and
             type(active["report"].get("input")) is dict and
             active["report"]["stage"].get("path") == pointer["stage"] and
             active["report"]["terminal"].get("boot_id") == pointer["boot_id"] and
             active["report"]["input"].get("candidate_sha256") ==
                 pointer["candidate_sha256"] and
             active.get("report_sha256") == hashlib.sha256(json.dumps(
                 active["report"], sort_keys=True, ensure_ascii=False,
                 separators=(",", ":")).encode()).hexdigest())
        sealed_report = active["report"]
    intent = strict_json(raw)
    base = {"schema", "old_active_sha256", "old_snapshot_sha256",
            "old_pointer_sha256", "verified_boot_sha256", "old_boot_id",
            "new_boot_id", "public_payload_root", "candidate_binary",
            "candidate_sha256", "installer_sha256"}
    optional = {"old_stopped_sha256", "old_pointer_receipt_sha256"}
    need(type(intent) is dict and set(intent) in (base, base | optional) and
         intent["schema"] == "aegis_auto_v2_boot_successor_v1" and
         pointer["boot_id"] == intent["new_boot_id"] == current_boot() and
         pointer["candidate_sha256"] == intent["candidate_sha256"] and
         type(intent["old_boot_id"]) is str and
         re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}",
                      intent["old_boot_id"]) and
         intent["old_boot_id"] != intent["new_boot_id"] and
         all(type(intent[key]) is str and re.fullmatch(r"[0-9a-f]{64}", intent[key])
             for key in ("old_active_sha256", "old_snapshot_sha256",
                         "old_pointer_sha256", "verified_boot_sha256",
                         "candidate_sha256", "installer_sha256")) and
         (not optional <= set(intent) or
          all(type(intent[key]) is str and re.fullmatch(r"[0-9a-f]{64}", intent[key])
              for key in optional)))
    root = absolute(intent["public_payload_root"])
    candidate = absolute(intent["candidate_binary"])
    need(root.parent == Path("/var/lib/aegis-auto/releases") and
         re.fullmatch(r"[A-Za-z0-9_-]+", root.name) and
         candidate == root / "bin/aegis-client")
    if sealed_report is not None:
        need(sealed_report["input"].get("public_payload_root") == str(root) and
             sealed_report["input"].get("candidate_binary") == str(candidate))
    if require_v3:
        need(pointer.get("schema") == "aegis_installer_auto_v2_boot_stage_v3" and
             pointer["boot_intent_sha256"] == hashlib.sha256(raw).hexdigest() and
             type(pointer.get("stage")) is str)
        handoff = []
        for leaf, sha in ((PREPARE_CURRENT, pointer["prepare_intent_sha256"]),
                          (PREPARE_COMPLETED, pointer["prepare_completed_sha256"])):
            fixed = archived = None
            try:
                fixed, _ = control_leaf(parent, leaf)
            except FileNotFoundError:
                pass
            try:
                archived, _ = control_leaf(parent, "prepare-archive-" + sha + ".json")
            except FileNotFoundError:
                pass
            need((fixed is not None or archived is not None) and
                 (fixed is None or archived is None or fixed == archived))
            item = fixed if fixed is not None else archived
            need(hashlib.sha256(item).hexdigest() == sha)
            handoff.append(item)
        prepared = strict_json(handoff[0])
        need(type(prepared) is dict and
             prepared.get("schema") == "aegis_auto_v2_boot_prepare_handoff_v2" and
             prepared.get("boot_intent_sha256") == pointer["boot_intent_sha256"] and
             prepared.get("stage") == pointer["stage"] and
             prepared.get("candidate_binary") == str(candidate) and
             prepared.get("public_payload_root") == str(root))
        paths = {"candidate-binary":candidate, "public-payload-root":root}
        need(admitted_prepare_handoff(Path(pointer["stage"]), paths, tuple(handoff),
                                      check_prepared_header=False) ==
             tuple(handoff))
        completed = strict_json(handoff[1])
        need(completed["boot_intent_sha256"] == pointer["boot_intent_sha256"] and
             completed["candidate_sha256"] == pointer["candidate_sha256"] and
             prepared["boot_id"] == pointer["boot_id"])
    return raw


def boot_completed_before_pointer(parent):
    """Recover only a boot-specific completed Prepare with durable provenance."""
    leaves = []
    for leaf in (PREPARE_CURRENT, PREPARE_COMPLETED):
        try:
            leaves.append(control_leaf(parent, leaf)[0])
        except FileNotFoundError:
            leaves.append(None)
    if leaves == [None, None]:
        return None
    need(all(type(raw) is bytes for raw in leaves))
    prepared, completed = map(strict_json, leaves)
    need(type(prepared) is dict and type(completed) is dict and
         prepared.get("schema") == "aegis_auto_v2_boot_prepare_handoff_v2" and
         completed.get("schema") == prepared["schema"] and
         type(prepared.get("boot_intent_sha256")) is str and
         completed.get("boot_intent_sha256") == prepared["boot_intent_sha256"] and
         type(completed.get("candidate_sha256")) is str)
    boot_raw = boot_pending_recovery_intent(parent, {
        "boot_id":current_boot(),
        "candidate_sha256":completed["candidate_sha256"]})
    need(hashlib.sha256(boot_raw).hexdigest() == prepared["boot_intent_sha256"])
    boot = strict_json(boot_raw)
    candidate = absolute(boot["candidate_binary"])
    root = absolute(boot["public_payload_root"])
    stage = absolute(prepared.get("stage"))
    need(stage.parent == Path("/run/aegis-installer-config-snapshots") and
         admitted_prepare_handoff(stage, {
             "candidate-binary":candidate,
             "public-payload-root":root}, tuple(leaves)) == tuple(leaves))
    verify_handoff_candidate(leaves[1], completed["candidate_sha256"])
    return candidate, prepared["boot_intent_sha256"]


def boot_partial_stage_manifest(stage_fd, stage_identity):
    """Hash only source-owned pre-header staging bytes; never consume them."""
    rows = []
    total = 0
    def walk(directory_fd, prefix, depth):
        nonlocal total
        need(depth <= 12 and len(rows) <= 1024)
        names = []
        with os.scandir(directory_fd) as entries:
            for entry in entries:
                need(len(names) < 1024)
                names.append(entry.name)
        names.sort()
        need(
             all(type(name) is str and 0 < len(name.encode()) <= 255 and
                 name not in (".", "..") and "/" not in name and
                 not any(ord(ch) < 32 for ch in name) for name in names))
        for name in names:
            relative = prefix + name
            need(len(relative.encode()) <= 1024 and len(rows) < 1024)
            info = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            need(info.st_uid == info.st_gid == 0 and info.st_dev == stage_identity.st_dev)
            if stat.S_ISDIR(info.st_mode):
                need(stat.S_IMODE(info.st_mode) == 0o700)
                child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW |
                                os.O_CLOEXEC, dir_fd=directory_fd)
                try:
                    held = os.fstat(child)
                    need((held.st_dev, held.st_ino, held.st_mode) ==
                         (info.st_dev, info.st_ino, info.st_mode))
                    rows.append({"path":relative,"type":"directory",
                                 "device":info.st_dev,"inode":info.st_ino})
                    walk(child, relative + "/", depth + 1)
                finally:
                    os.close(child)
            else:
                need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and
                     stat.S_IMODE(info.st_mode) == 0o600 and
                     0 <= info.st_size <= 96 << 20 and
                     total + info.st_size <= 256 << 20)
                fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK |
                             os.O_CLOEXEC, dir_fd=directory_fd)
                try:
                    held = os.fstat(fd)
                    need((held.st_dev, held.st_ino, held.st_size, held.st_mode) ==
                         (info.st_dev, info.st_ino, info.st_size, info.st_mode))
                    digest = hashlib.sha256()
                    count = 0
                    while block := os.read(fd, 65536):
                        count += len(block)
                        need(count <= info.st_size)
                        digest.update(block)
                    after = os.fstat(fd)
                    need(count == info.st_size and
                         (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns,
                          after.st_ctime_ns) ==
                         (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns,
                          info.st_ctime_ns))
                    total += count
                    rows.append({"path":relative,"type":"file",
                                 "device":info.st_dev,"inode":info.st_ino,
                                 "size":count,"sha256":digest.hexdigest()})
                finally:
                    os.close(fd)
    need(stat.S_ISDIR(stage_identity.st_mode) and
         stage_identity.st_uid == stage_identity.st_gid == 0 and
         stat.S_IMODE(stage_identity.st_mode) == 0o700)
    walk(stage_fd, "", 0)
    # Even a torn or finalized-looking header is retained as opaque evidence.
    # The stage-created receipt owns the inode, while this manifest grants no
    # worker or activation authority. No header bytes are interpreted here.
    return rows


def retire_boot_prepare_without_stage():
    """Archive an exact boot intent only when no stage was ever published."""
    install_fd = _open_original_lock("/run/aegis-auto-install.lock", 9)
    try:
        parent = control_directory()
        history_dir = None
        try:
            need(current_pointer(parent) is None)
            raw, identity = control_leaf(parent, PREPARE_CURRENT)
            try:
                control_leaf(parent, PREPARE_COMPLETED)
            except FileNotFoundError:
                pass
            else:
                raise Refused()
            prepared = strict_json(raw)
            need(type(prepared) is dict and set(prepared) == {
                "schema", "phase", "boot_id", "stage", "candidate_binary",
                "public_payload_root", "nonce", "boot_intent_sha256"} and
                 prepared["schema"] == "aegis_auto_v2_boot_prepare_handoff_v2" and
                 prepared["phase"] == "intent" and
                 prepared["boot_id"] == current_boot() and
                 type(prepared["nonce"]) is str and
                 re.fullmatch(r"[0-9a-f]{32}", prepared["nonce"]) and
                 type(prepared["boot_intent_sha256"]) is str and
                 re.fullmatch(r"[0-9a-f]{64}", prepared["boot_intent_sha256"]))
            stage = absolute(prepared["stage"])
            need(stage.parent == Path("/run/aegis-installer-config-snapshots") and
                 re.fullmatch(r"\.auto-[0-9a-f]{32}", stage.name))
            boot_leaf, _ = control_leaf(parent, "generation-boot-successor-current.json", 8192)
            boot = strict_json(boot_leaf)
            need(type(boot) is dict and type(boot.get("candidate_sha256")) is str)
            again = boot_pending_recovery_intent(parent, {
                "boot_id":current_boot(), "candidate_sha256":boot["candidate_sha256"]})
            need(again == boot_leaf and
                 hashlib.sha256(again).hexdigest() == prepared["boot_intent_sha256"] and
                 prepared["candidate_binary"] == boot["candidate_binary"] and
                 prepared["public_payload_root"] == boot["public_payload_root"])
            intent_sha = hashlib.sha256(raw).hexdigest()
            journal_leaf = "prepare-quarantine-" + intent_sha + ".json"
            history_dir = os.open("generation-history", os.O_RDONLY | os.O_DIRECTORY |
                                  os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
            history_info = os.fstat(history_dir)
            need(stat.S_ISDIR(history_info.st_mode) and
                 history_info.st_uid == history_info.st_gid == 0 and
                 stat.S_IMODE(history_info.st_mode) == 0o700)
            try:
                journal_raw, _ = control_leaf(history_dir, journal_leaf, 1 << 20)
                journal = strict_json(journal_raw)
            except FileNotFoundError:
                journal_raw = journal = None
            if journal is not None:
                need(type(journal) is dict and set(journal) == {
                    "schema", "prepare_intent_sha256", "stage_created_sha256",
                    "stage", "quarantine", "stage_device", "stage_inode",
                    "files"} and
                     journal["schema"] == "aegis_auto_v2_boot_prepare_quarantine_v1" and
                     journal["prepare_intent_sha256"] == intent_sha and
                     type(journal["stage_created_sha256"]) is str and
                     re.fullmatch(r"[0-9a-f]{64}", journal["stage_created_sha256"]) and
                     journal["stage"] == str(stage) and
                     type(journal["files"]) is list)
            try:
                created_raw, created_identity = control_leaf(parent, PREPARE_STAGE_CREATED)
            except FileNotFoundError:
                created_identity = None
                if journal is None:
                    created_raw = None
                else:
                    created_raw, _ = control_leaf(parent,
                        "prepare-archive-" + journal["stage_created_sha256"] + ".json")
            created = strict_json(created_raw) if created_raw is not None else None
            if created is not None:
                need(type(created) is dict and set(created) == {
                    "schema", "prepare_intent_sha256", "boot_intent_sha256",
                    "boot_id", "stage", "stage_device", "stage_inode",
                    "candidate_binary", "public_payload_root"} and
                     created["schema"] == "aegis_auto_v2_boot_stage_created_v1" and
                     created["prepare_intent_sha256"] == hashlib.sha256(raw).hexdigest() and
                     created["boot_intent_sha256"] == prepared["boot_intent_sha256"] and
                     created["boot_id"] == prepared["boot_id"] and
                     created["stage"] == str(stage) and
                     created["candidate_binary"] == prepared["candidate_binary"] and
                     created["public_payload_root"] == prepared["public_payload_root"] and
                     all(type(created[key]) is int and created[key] > 0 for key in
                         ("stage_device", "stage_inode")))
                need(journal is None or
                     hashlib.sha256(created_raw).hexdigest() ==
                         journal["stage_created_sha256"])
            else:
                need(journal is None)
            # The authorized boot coordinator starts no worker until both
            # Prepare completion and current.json are durable. Still refuse
            # any contrary retained terminal or archived completion before
            # moving this inode; the journal preserves every stage byte.
            names = os.listdir(parent)
            need(len(names) <= 4096)
            for name in names:
                if re.fullmatch(r"prepare-archive-[0-9a-f]{64}\.json", name):
                    candidate_archive, _ = control_leaf(parent, name)
                    candidate_record = strict_json(candidate_archive)
                    need(type(candidate_record) is dict)
                    need(not (candidate_record.get("phase") == "completed" and
                              candidate_record.get("intent_sha256") == intent_sha))
            try:
                active_raw, _ = control_leaf(parent, "generation.json", 139264)
            except FileNotFoundError:
                pass
            else:
                active = strict_json(active_raw)
                need(type(active) is dict and type(active.get("report")) is dict and
                     type(active["report"].get("stage")) is dict and
                     active["report"]["stage"].get("path") != str(stage))
            _abort_unit_barrier(allow_active=False)
            stage_parent = directory(stage.parent)
            try:
                stage_info = os.fstat(stage_parent)
                need(stat.S_ISDIR(stage_info.st_mode) and
                     stage_info.st_uid == stage_info.st_gid == 0 and
                     stat.S_IMODE(stage_info.st_mode) == 0o700)
                quarantine = (".failed-boot-prepare-" +
                              hashlib.sha256(raw).hexdigest())
                try:
                    stage_fd = os.open(stage.name, os.O_RDONLY | os.O_DIRECTORY |
                                       os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=stage_parent)
                except FileNotFoundError:
                    stage_fd = None
                else:
                    try:
                        info = os.fstat(stage_fd)
                        need(stat.S_ISDIR(info.st_mode) and
                             info.st_uid == info.st_gid == 0 and
                             stat.S_IMODE(info.st_mode) == 0o700)
                        need(created is None or (info.st_dev, info.st_ino) ==
                             (created["stage_device"], created["stage_inode"]))
                        files = boot_partial_stage_manifest(stage_fd, info)
                        need(created is not None or files == [])
                        if created is not None:
                            expected_journal = {
                                "schema":"aegis_auto_v2_boot_prepare_quarantine_v1",
                                "prepare_intent_sha256":intent_sha,
                                "stage_created_sha256":hashlib.sha256(created_raw).hexdigest(),
                                "stage":str(stage),"quarantine":quarantine,
                                "stage_device":info.st_dev,"stage_inode":info.st_ino,
                                "files":files}
                            if journal is None:
                                journal_raw = json.dumps(expected_journal,
                                    sort_keys=True, separators=(",", ":")).encode()
                                need(len(journal_raw) <= 1 << 20)
                                atomic_exclusive_bytes(history_dir, journal_leaf, journal_raw)
                                need(control_leaf(history_dir, journal_leaf, 1 << 20)[0] == journal_raw)
                                journal = expected_journal
                            else:
                                need(journal == expected_journal)
                        # Before any stage leaf or lock file exists, a crash
                        # leaves only this private empty directory. Preserve
                        # it under a deterministic exact-intent name; never
                        # replace another path or recursively remove bytes.
                        libc = ctypes.CDLL(None, use_errno=True)
                        rename = libc.renameat2
                        rename.argtypes = (ctypes.c_int, ctypes.c_char_p,
                                           ctypes.c_int, ctypes.c_char_p, ctypes.c_uint)
                        rename.restype = ctypes.c_int
                        if rename(stage_parent, stage.name.encode(), stage_parent,
                                  quarantine.encode(), 1) != 0:
                            error = ctypes.get_errno()
                            raise OSError(error, os.strerror(error))
                        os.fsync(stage_parent)
                    finally:
                        os.close(stage_fd)
                quarantined = None
                try:
                    quarantined = os.open(quarantine, os.O_RDONLY | os.O_DIRECTORY |
                                          os.O_NOFOLLOW | os.O_CLOEXEC,
                                          dir_fd=stage_parent)
                except FileNotFoundError:
                    pass
                else:
                    try:
                        info = os.fstat(quarantined)
                        need(stat.S_ISDIR(info.st_mode) and
                             info.st_uid == info.st_gid == 0 and
                             stat.S_IMODE(info.st_mode) == 0o700)
                        need(created is None or (info.st_dev, info.st_ino) ==
                             (created["stage_device"], created["stage_inode"]))
                        files = boot_partial_stage_manifest(quarantined, info)
                        if created is None:
                            need(files == [])
                        else:
                            need(journal is not None and journal["files"] == files and
                                 journal["quarantine"] == quarantine and
                                 journal["stage_device"] == info.st_dev and
                                 journal["stage_inode"] == info.st_ino)
                    finally:
                        os.close(quarantined)
                if created is not None:
                    need(quarantined is not None)
            finally:
                os.close(stage_parent)
            fresh_package_lock(install_fd)
            if created_raw is not None:
                created_archive = ("prepare-archive-" +
                                   hashlib.sha256(created_raw).hexdigest() + ".json")
                try:
                    archived_created, _ = control_leaf(parent, created_archive)
                    need(archived_created == created_raw)
                except FileNotFoundError:
                    atomic_exclusive_bytes(parent, created_archive, created_raw)
                    need(control_leaf(parent, created_archive)[0] == created_raw)
            archive = "prepare-archive-" + hashlib.sha256(raw).hexdigest() + ".json"
            try:
                archived, _ = control_leaf(parent, archive)
                need(archived == raw)
            except FileNotFoundError:
                atomic_exclusive_bytes(parent, archive, raw)
                need(control_leaf(parent, archive)[0] == raw)
            last, observed = control_leaf(parent, PREPARE_CURRENT)
            need(last == raw and (observed.st_dev, observed.st_ino) ==
                 (identity.st_dev, identity.st_ino))
            if created_raw is not None:
                if created_identity is not None:
                    last_created, observed_created = control_leaf(parent, PREPARE_STAGE_CREATED)
                    need(last_created == created_raw and
                         (observed_created.st_dev, observed_created.st_ino) ==
                         (created_identity.st_dev, created_identity.st_ino))
                    os.unlink(PREPARE_STAGE_CREATED, dir_fd=parent)
                    os.fsync(parent)
            os.unlink(PREPARE_CURRENT, dir_fd=parent)
            os.fsync(parent)
            fresh_package_lock(install_fd)
        finally:
            if history_dir is not None:
                os.close(history_dir)
            os.close(parent)
    finally:
        os.close(install_fd)


def boot_current():
    """Start a fresh-boot generation through the same production V2 worker.

    The installed Rust boundary authenticates historical source and current
    boot/roots/PID1/guard/host observations before retiring the old pointer.
    Python receives no reusable activation authority from that history.
    """
    need(sys.platform == "linux" and os.geteuid() == 0)
    installed = Path("/usr/local/bin/aegis-client")
    progress = {"phase": "boot_successor", "worker": None, "worker_started": None}
    # A crash after the new pending pointer was published cannot replay the
    # old boot-successor retirement: that boundary has no new report authority
    # and must keep its predecessor-pointer checks strict. Select only the
    # existing same-boot recovery boundary, which authenticates the pending
    # stage, candidate and terminal or rollback under its own held locks.
    try:
        parent = control_directory()
        try:
            pending = current_pointer(parent)
            incomplete_cut = False
            if pending is None:
                try:
                    control_leaf(parent, PREPARE_CURRENT)
                except FileNotFoundError:
                    pass
                else:
                    try:
                        control_leaf(parent, PREPARE_COMPLETED)
                    except FileNotFoundError:
                        incomplete_cut = True
            completed_cut = (boot_completed_before_pointer(parent)
                             if pending is None and not incomplete_cut else None)
            pending_this_boot = pending is not None and pending[0]["boot_id"] == current_boot()
            if pending_this_boot:
                boot_pending_recovery_intent(parent, pending[0], require_v3=True)
        finally:
            os.close(parent)
        if incomplete_cut:
            try:
                call_output([str(installed), "profile", "auto-config",
                             "complete-boot-prepare"], maximum=4096, timeout=120,
                            diagnostic_stderr=True)
            except Refused:
                # Only the separate original-lock inverse may interpret an
                # absent/pre-header stage. A complete or malformed header,
                # changed receipt, timeout actor or foreign path stays sticky.
                retire_boot_prepare_without_stage()
            else:
                parent = control_directory()
                try:
                    completed_cut = boot_completed_before_pointer(parent)
                    need(completed_cut is not None)
                finally:
                    os.close(parent)
        if completed_cut is not None:
            recover_prepare_handoff(completed_cut[0],
                                    boot_intent_sha256=completed_cut[1])
            parent = control_directory()
            try:
                pending = current_pointer(parent)
                need(pending is not None and pending[0]["boot_id"] == current_boot())
                boot_pending_recovery_intent(parent, pending[0], require_v3=True)
            finally:
                os.close(parent)
            pending_this_boot = True
        if pending_this_boot:
            recovered = recover_current(installed, expected_pointer=pending[1])
            if recovered == "terminal_active":
                return "boot_active"
            need(recovered in ("recovered", "recovered_stopped"))
            parent = control_directory()
            try:
                need(current_pointer(parent) is None)
            finally:
                os.close(parent)
            # Reopen the installed ELF below. Recovery may have restored the
            # predecessor binary, so no old descriptor or hash is reused.
    except Exception as error:
        try:
            record_failure(progress, error)
        except Exception:
            pass
        raise
    descriptor = held_root_file(installed, 256 << 20, (0o555, 0o755))
    try:
        installed_sha = file_sha(descriptor)[1]
    finally:
        os.close(descriptor)
    try:
        _set_phase("boot_successor")
        raw = call_output([str(installed), "profile", "auto-config",
                           "begin-boot-successor"], maximum=8192, timeout=420,
                          closed_boot_phase=True)
        proof = strict_json(raw)
        need(type(proof) is dict and
             proof.get("schema") == "aegis_auto_v2_boot_successor_verification_v1" and
             proof.get("new_boot_id") == current_boot() and
             proof.get("old_boot_id") != current_boot() and
             type(proof.get("intent_sha256")) is str and
             re.fullmatch(r"[0-9a-f]{64}", proof["intent_sha256"]) and
             proof.get("candidate_sha256") == installed_sha)
        root = absolute(proof["public_payload_root"])
        candidate = absolute(proof["candidate_binary"])
        need(root.parent == Path("/var/lib/aegis-auto/releases") and
             candidate == root / "bin/aegis-client")
        installer = bounded_root_bytes(root / "install.sh", 8 << 20,
                                       (0o555, 0o755))
        need(hashlib.sha256(installer).hexdigest() == proof["installer_sha256"])
        candidate_fd = held_root_file(candidate, 256 << 20, (0o555, 0o755))
        try:
            need(file_sha(candidate_fd)[1] == installed_sha)
        finally:
            os.close(candidate_fd)
        parent = control_directory()
        try:
            boot_raw = boot_pending_recovery_intent(parent, {
                "boot_id":current_boot(),"candidate_sha256":installed_sha})
            need(hashlib.sha256(boot_raw).hexdigest() == proof["intent_sha256"])
        finally:
            os.close(parent)
    except Exception as error:
        phase = getattr(error, "boot_failure_phase", None)
        if isinstance(error, Refused) and phase in _BOOT_FAILURE_PHASES:
            print(f"AUTO_V2_BOOT_REFUSED phase={phase}", file=sys.stderr)
        try:
            record_failure(progress, error)
        except Exception:
            pass
        raise
    args = parser().parse_args([
        "install", "--config-root", "/etc/aegis/client",
        "--state-dir", "/var/lib/aegis-client",
        "--metadata-dir", "/var/lib/aegis-install/auto-client",
        "--staging-parent", "/run/aegis-installer-config-snapshots",
        "--public-payload-root", str(root), "--candidate-binary", str(candidate),
        "--installed-binary", str(installed),
        "--runtime-events", str(AUTO_RUNTIME_EVENTS),
        "--existing-choice", "upgrade"])
    args._boot_intent_sha256 = proof["intent_sha256"]
    return "boot_active" if run(args) else None


def _abort_private_tree(path, *, maximum=1 << 30, file_max=PASSIVE_FILE_MAX):
    """Record exact regular-file bytes and ownership, without returning contents."""
    root = absolute(str(path))
    entries = []
    total = 0

    def walk(current, relative):
        nonlocal total
        info = current.lstat()
        need(info.st_uid == info.st_gid == 0 and info.st_nlink >= 1 and
             not stat.S_IMODE(info.st_mode) & 0o022)
        entry = {"path": relative, "dev": info.st_dev, "ino": info.st_ino,
                 "mode": info.st_mode, "uid": info.st_uid, "gid": info.st_gid,
                 "nlink": info.st_nlink, "size": info.st_size,
                 "mtime_ns": info.st_mtime_ns}
        if stat.S_ISDIR(info.st_mode):
            need(len(entries) < 256)
            entries.append(entry)
            names = sorted(os.listdir(current))
            need(len(names) <= 128 and all(re.fullmatch(r"[A-Za-z0-9_.-]{1,128}",
                                              name) and name not in (".", "..")
                                            for name in names))
            for name in names:
                walk(current / name, relative + "/" + name)
        else:
            need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and
                 0 < info.st_size <= file_max)
            fd = held_root_file(current, file_max)
            try:
                size, sha = bounded_digest(fd, file_max)
            finally:
                os.close(fd)
            need(size == info.st_size)
            total += size
            need(total <= maximum and len(entries) < 256)
            entry["sha256"] = sha
            entries.append(entry)

        after = current.lstat()
        need(all(getattr(info, field) == getattr(after, field) for field in
                 ("st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_nlink",
                  "st_size", "st_mtime_ns")))

    walk(root, ".")
    return entries


def _abort_failure_history(parent, *, recovered=False):
    """Admit prior failures as bounded inert evidence, never phase authority."""
    names = sorted(name for name in os.listdir(parent)
                   if name.startswith("failure-"))
    need(len(names) <= 32)
    recovered_failures = 0
    for name in names:
        need(re.fullmatch(r"failure-[0-9a-f]{32}\.json", name))
        raw = bounded_root_bytes(CONTROL / name, 512, (0o600,))
        value = strict_json(raw)
        need(type(value) is dict and set(value) == {
            "schema", "phase", "reason", "worker_exit", "remaining_ms"} and
             value["schema"] == "aegis_installer_auto_v2_failure_v1")
        old = (value["phase"] in ("preflight", "prepare") and
               value["reason"] in ("refused", "timeout", "os_error", "unexpected") and
               value["worker_exit"] is None and value["remaining_ms"] is None)
        account = (recovered and value["phase"] == "account" and
                   value["reason"] == "refused" and value["worker_exit"] == 1 and
                   type(value["remaining_ms"]) is int and
                   0 <= value["remaining_ms"] <= 900000)
        need(old or account)
        recovered_failures += int(account)
    if recovered:
        need(recovered_failures == 1)
    return names


def _abort_original_facts(install_fd, *, recovered=None):
    """Authenticate the still passive A installation before publishing intent."""
    fresh_package_lock(install_fd)
    parent = _passive_control()
    try:
        intent = _passive_record(parent, PASSIVE_INTENT)
        _passive_intent_shape(intent)
        need(intent["fresh_origin"] == "packaged" and
             intent["boot_id"] == current_boot() and
             _passive_identity(intent["source"]["public_payload_root"],
                               "packaged") == intent["source"])
        _passive_installed_origin(intent["source"], install_fd)
        failures = _abort_failure_history(parent, recovered=recovered is not None)
        # A refused host/boot assessment precedes FIRST_ARM_INTENT and leaves
        # inert diagnostics. Apply the same bounded inode checks as passive
        # retry; the complete CONTROL tree is archived, never used as authority.
        orphans = _passive_assessment_orphans(parent)
        extra = () if recovered is None else recovered["control_leaves"]
        names = _passive_names(parent, (PASSIVE_INTENT, PASSIVE_INPUT,
                                        PASSIVE_READY, "v2-enabled", *failures,
                                        *orphans, *extra))
        need(PASSIVE_INTENT in names and PASSIVE_INPUT in names and
             PASSIVE_READY in names and "v2-enabled" in names and
             not any(name.startswith(".passive-tmp-") for name in os.listdir(parent)))
        ready = _passive_record(parent, PASSIVE_READY)
        intent_sha = hashlib.sha256(bounded_root_bytes(
            CONTROL / PASSIVE_INTENT, 16384, (0o600,))).hexdigest()
        need(ready == {"schema": "aegis_auto_v2_fresh_passive_ready_v1",
                       "boot_id": intent["boot_id"], "intent_sha256": intent_sha,
                       "candidate_sha256": intent["source"]["candidate_sha256"]})
        need(bounded_root_bytes(CONTROL / "v2-enabled", 128, (0o600,)) ==
             b'{"schema":"aegis_installer_auto_v2_enabled_v1"}\n')
        snapshot = CONTROL / PASSIVE_INPUT
        snapshot_fd = directory(snapshot, 0o700)
        try:
            expected = {name for name, entry in intent["bundle_files"].items()
                        if entry is not None}
            expected |= {ref["snapshot_relative"].split("/")[0]
                         for ref in intent["external_refs"]
                         if ref["snapshot_relative"] is not None}
            need(set(os.listdir(snapshot_fd)) == expected)
        finally:
            os.close(snapshot_fd)
        for name, entry in intent["bundle_files"].items():
            if entry is not None:
                raw = bounded_root_bytes(snapshot / name, PASSIVE_FILE_MAX, (0o600,))
                need(len(raw) == entry["size"] and
                     hashlib.sha256(raw).hexdigest() == entry["sha256"])
        for ref in intent["external_refs"]:
            if ref["snapshot_relative"] is not None:
                raw = bounded_root_bytes(snapshot / ref["snapshot_relative"],
                                         PASSIVE_FILE_MAX, (0o600,))
                need(len(raw) == ref["size"] and
                     hashlib.sha256(raw).hexdigest() == ref["sha256"])
        for path in (CONTROL / FIRST_ARM_INTENT, CONTROL / POINTER,
                     CONTROL / PREPARE_CURRENT, CONTROL / PREPARE_COMPLETED,
                     CONTROL / PREPARE_STAGE_CREATED,
                     CONTROL / "generation-active-current.json",
                     CONTROL / "generation-stopped-current.json",
                     CONTROL / "generation-successor-current.json",
                     Path("/var/lib/aegis-install/client/device-guard.conf"),
                     Path("/var/lib/aegis-install/client/device-guard.conf.capture-binding"),
                     Path("/var/lib/aegis-install/client/device-guard.conf.main-binding"),
                     Path("/var/lib/aegis-install/client/auto-stage-owner.json"),
                     Path("/var/lib/aegis-install/client/auto-stop-intent.json"),
                     Path("/var/lib/aegis-install/client/auto-watchdog-pending.json"),
                     Path("/var/lib/aegis-install/client/auto-guard-rotation-intent.json"),
                     Path("/var/lib/aegis-install/auto-client/wide-profile.json"),
                     Path("/etc/systemd/system/aegis-device-egress-guard.service"),
                     Path("/etc/systemd/system/aegis-client.service"),
                     Path("/etc/aegis/client/aegis.toml"),
                     Path("/etc/aegis/aegis.toml")):
            need(not path.exists() and not path.is_symlink())
        stage = Path("/run/aegis-installer-config-snapshots")
        if stage.exists() or stage.is_symlink():
            stage_fd = directory(stage)
            try:
                expected_stage = set() if recovered is None else {
                    Path(recovered["stage"]).name}
                need(set(os.listdir(stage_fd)) == expected_stage)
            finally:
                os.close(stage_fd)
        for path in (Path("/etc/aegis/client"), Path("/var/lib/aegis-client"),
                     Path("/var/lib/aegis-install/auto-client")):
            if path.exists() or path.is_symlink():
                fd = directory(path)
                try:
                    need(not os.listdir(fd))
                finally:
                    os.close(fd)
        _passive_gate_dropins(Path("/etc/systemd/system/aegis-client.service.d"))
        root = Path(intent["source"]["public_payload_root"])
        for leaf in FRESH_CLIENT_HELPERS:
            source_path, mode = retained_client_helper_source(root, leaf)
            expected = bounded_root_bytes(source_path, 4 << 20,
                                          (0o444, 0o555))
            modes = (0o644, 0o755) if leaf == "lib/root-state.sh" else (mode,)
            need(bounded_root_bytes(Path("/usr/local/lib/aegis/helpers") / leaf,
                                    4 << 20, modes) == expected)
        for leaf in FRESH_CLIENT_UNITS:
            need(bounded_root_bytes(Path("/etc/systemd/system") / leaf,
                                    1 << 20, (0o644,)) ==
                 bounded_root_bytes(root / "packaging/systemd" / leaf,
                                    1 << 20, (0o444,)))
        metadata = Path("/var/lib/aegis-install/client")
        metadata_fd = directory(metadata)
        try:
            need(set(os.listdir(metadata_fd)) == {"auto-guardian-install.json"})
        finally:
            os.close(metadata_fd)
        installed = Path("/usr/local/lib/aegis/helpers/lib/aegis_auto_guardian.py")
        spec = importlib.util.spec_from_file_location("aegis_auto_guardian_abort", installed)
        need(spec is not None and spec.loader is not None)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        module.own_source()
        provision = module.record(module.INSTALL)
        need(provision == module.provision_receipt(root / "bin/aegis-client") and
             provision["guard_unit_sha256"] is None)
        return intent, {"failure_count": len(failures),
                        "intent_sha256": intent_sha,
                        "provision_sha256": hashlib.sha256(bounded_root_bytes(
                            metadata / "auto-guardian-install.json", 16384,
                            (0o600,))).hexdigest()}
    finally:
        os.close(parent)


def _abort_unit_facts(unit):
    timer = unit.endswith(".timer")
    fields = ("Id", "LoadState", "ActiveState", "SubState", "NeedDaemonReload",
              "UnitFileState", "FragmentPath", "DropInPaths", "Triggers",
              "TriggeredBy", "WantedBy", "RequiredBy", "BoundBy",
              "UpheldBy")
    if not timer:
        fields += ("MainPID", "ControlPID", "ControlGroup", "InvocationID",
                   "NFileDescriptorStore")
    command = ["/usr/bin/systemctl", "show", unit, "--no-pager"]
    for field in fields:
        command.extend(("-p", field))
    raw = call_output(command, maximum=4096, timeout=5)
    facts = {}
    for line in raw.decode("ascii").splitlines():
        key, sep, value = line.partition("=")
        need(sep and key not in facts)
        facts[key] = value
    need(set(facts) == set(fields) and facts["Id"] == unit and
         facts["NeedDaemonReload"] == "no")
    return facts


def _abort_admin_present(unit):
    path = Path("/etc/systemd/system") / unit
    return path.exists() or path.is_symlink()


def _abort_unit_quiescent(unit, *, allow_active=False):
    facts = _abort_unit_facts(unit)
    admin = Path("/etc/systemd/system") / unit
    if unit == "aegis-client.service":
        need(facts["LoadState"] == "loaded" and
             facts["FragmentPath"] ==
             "/usr/lib/systemd/system/aegis-client.service" and
             facts["UnitFileState"] == "disabled")
        gate = Path("/etc/systemd/system/aegis-client.service.d/00-v2-boot-gate.conf")
        need(facts["DropInPaths"] == (str(gate) if gate.exists() else ""))
    elif _abort_admin_present(unit):
        need(facts["LoadState"] == "loaded" and
             facts["FragmentPath"] == str(admin) and
             facts["DropInPaths"] == "" and
             facts["UnitFileState"] == (
                 "disabled" if unit in ("aegis-auto-guardian.service",
                                        "aegis-auto-witness-topology.service",
                                        "aegis-auto-config.service",
                                        "aegis-auto-terminal-observer.service",
                                        "aegis-foreign-policy-monitor.service",
                                        "aegis-auto-clean-shutdown.service",
                                        "aegis-device-dhcp-refresh.timer") else "static"))
    else:
        need(facts["LoadState"] == "not-found" and
             facts["FragmentPath"] == facts["DropInPaths"] ==
             facts["UnitFileState"] == "")
    if unit == "aegis-auto-trace-rollback.timer" and facts["LoadState"] == "loaded":
        need(facts["Triggers"] == "aegis-auto-trace-rollback.service" and
             facts["TriggeredBy"] == "")
    elif unit == "aegis-device-dhcp-refresh.timer" and facts["LoadState"] == "loaded":
        need(facts["Triggers"] == "aegis-device-dhcp-refresh.service" and
             facts["TriggeredBy"] == "")
    elif unit == "aegis-auto-trace-rollback.service" and facts["LoadState"] == "loaded":
        need(facts["Triggers"] == "" and
             facts["TriggeredBy"] in ("", "aegis-auto-trace-rollback.timer"))
    else:
        need(facts["Triggers"] == facts["TriggeredBy"] == "")
    allowed_required_by = {
        "aegis-auto-guardian.service": {"aegis-auto-config.service"},
        "aegis-auto-guardian-watchdog.service": {"aegis-auto-guardian.service"},
        "aegis-auto-witness-topology.service": {"aegis-auto-guardian.service"},
        "aegis-auto-trace-rollback-actor.service": {"aegis-auto-guardian.service"},
        "aegis-device-egress-guard.service": {
            "aegis-auto-capture-topology.service"},
    }
    need(facts["WantedBy"] == facts["BoundBy"] == facts["UpheldBy"] == "" and
         set(facts["RequiredBy"].split()) <= allowed_required_by.get(unit, set()))
    if not unit.endswith(".timer"):
        need(facts["ControlPID"] == "0" and
             facts["NFileDescriptorStore"] == "0")
    if allow_active and facts["ActiveState"] == "active":
        need(not unit.endswith(".timer") and facts["LoadState"] == "loaded" and
             facts["SubState"] == "running" and int(facts["MainPID"]) > 1 and
             facts["ControlGroup"] == "/system.slice/" + unit)
        return facts
    need(facts["ActiveState"] == "inactive" and facts["SubState"] == "dead")
    if not unit.endswith(".timer"):
        need(facts["MainPID"] == "0" and facts["ControlGroup"] == "" and
             (facts["InvocationID"] in ("", "0" * 32) or
              re.fullmatch(r"[0-9a-fA-F]{32}", facts["InvocationID"])))
    return facts


def _abort_actor_states(*, allow_active):
    states = []
    no_private_jobs_or_units()
    for unit, socket, source in PASSIVE_ACTORS:
        facts = _abort_unit_quiescent(unit, allow_active=allow_active)
        if facts["ActiveState"] == "active":
            pid = int(facts["MainPID"])
            need(facts["ControlGroup"] == "/system.slice/" + unit and
                 Path(f"/proc/{pid}/cgroup").read_text() ==
                 "0::/system.slice/" + unit + "\n")
            with open(f"/proc/{pid}/cmdline", "rb", buffering=0) as process:
                need(process.read(1025) ==
                     ("/usr/bin/python3\0-I\0-B\0/usr/local/lib/aegis/helpers/lib/" +
                      source + "\0serve\0").encode())
            handle = os.pidfd_open(pid, 0)
            try:
                poller = select.poll()
                poller.register(handle, select.POLLIN | select.POLLHUP | select.POLLERR)
                need(not poller.poll(0))
            finally:
                os.close(handle)
            actor_socket_owner(Path(socket), pid)
        else:
            if (unit == "aegis-auto-witness-topology.service" and
                    (Path(socket).exists() or Path(socket).is_symlink())):
                _abort_stale_witness_socket()
            else:
                need(not Path(socket).exists() and not Path(socket).is_symlink())
        states.append({"unit": unit, "active": facts["ActiveState"] == "active",
                       "invocation_id": facts["InvocationID"]})
    return states


def _abort_no_source_processes():
    commands = {("/usr/local/lib/aegis/helpers/lib/" + source).encode()
                for _unit, _socket, source in PASSIVE_ACTORS}
    for entry in os.scandir("/proc"):
        if not entry.name.isdecimal():
            continue
        try:
            with open(entry.path + "/cmdline", "rb", buffering=0) as source:
                argv = source.read(2048).split(b"\0")
        except (FileNotFoundError, ProcessLookupError):
            continue
        need(not any(item in commands for item in argv))


def _abort_socket_metadata(path):
    info = path.lstat()
    need(stat.S_ISSOCK(info.st_mode) and info.st_uid == info.st_gid == 0 and
         info.st_nlink == 1 and stat.S_IMODE(info.st_mode) == 0o600)
    return {"dev": info.st_dev, "ino": info.st_ino, "mode": info.st_mode,
            "uid": info.st_uid, "gid": info.st_gid, "nlink": info.st_nlink,
            "mtime_ns": info.st_mtime_ns}


def _abort_stale_witness_socket():
    runtime = directory(PASSIVE_ABORT_WITNESS_SOCKET.parent, 0o700)
    try:
        need("authority.sock" in os.listdir(runtime))
    finally:
        os.close(runtime)
    metadata = _abort_socket_metadata(PASSIVE_ABORT_WITNESS_SOCKET)
    with open("/proc/net/unix", "rb", buffering=0) as source:
        table = read_unix_table(source)
    need(not unix_table_socket_inodes(table, PASSIVE_ABORT_WITNESS_SOCKET))
    _abort_no_source_processes()
    return metadata


def _abort_no_effects(*, allow_actor_processes=False, recovered_stage=None):
    for path in ("/var/lib/aegis-install/client/device-guard.conf",
                 "/var/lib/aegis-install/client/device-guard.conf.capture-binding",
                 "/var/lib/aegis-install/client/device-guard.conf.main-binding",
                 "/var/lib/aegis-install/client/auto-stage-owner.json",
                 "/var/lib/aegis-install/client/auto-watchdog-pending.json",
                 "/var/lib/aegis-install/client/auto-stop-intent.json",
                 "/var/lib/aegis-install/client/auto-guard-rotation-intent.json",
                 "/var/lib/aegis-install/auto-client/wide-profile.json",
                 "/var/lib/aegis-install/client/auto-capture-relay-install.json",
                 "/etc/systemd/system/aegis-device-egress-guard.service",
                 "/var/lib/aegis-auto/control/current.json",
                 "/var/lib/aegis-auto/control/prepare-current.json",
                 "/var/lib/aegis-auto/control/prepare-completed.json",
                 "/var/lib/aegis-auto/control/prepare-stage-created.json",
                 "/var/lib/aegis-auto/control/fresh-first-arm-intent.json",
                 "/run/aegis-installer-config-snapshots"):
        target = Path(path)
        if target.name == "aegis-installer-config-snapshots" and target.exists():
            fd = directory(target)
            try:
                expected = set() if recovered_stage is None else (
                    {Path(recovered_stage).name} if Path(recovered_stage).parent == target and
                    Path(recovered_stage).exists() else set())
                need(set(os.listdir(fd)) == expected)
            finally:
                os.close(fd)
        else:
            need(not target.exists() and not target.is_symlink())
    table = strict_json(call_output(["/usr/sbin/nft", "--json", "list", "tables"],
                                    maximum=1 << 20, timeout=5))
    need(type(table) is dict and type(table.get("nftables")) is list)
    for item in table["nftables"]:
        if type(item) is dict and type(item.get("table")) is dict:
            name = item["table"].get("name")
            need(type(name) is str and not name.startswith("aegis_"))
    _abort_capture_absent()
    if not allow_actor_processes:
        _abort_no_source_processes()


def _abort_capture_absent():
    """A capture object would contradict the never-first-arm certificate."""
    for path in (
        "/var/lib/aegis-install/client/auto-capture-relay-install.json",
        "/run/aegis-auto-capture-topology/owned-state.json",
        "/run/aegis-auto-capture-topology/fixture.json",
        "/run/aegis-auto-capture-topology/authority.sock",
        "/run/netns/aegisac-relay", "/run/netns/aegisac-sink",
        "/run/netns/aegisac-probe", "/sys/class/net/aegisacr0",
        "/sys/class/net/aegisacr1", "/sys/class/net/aegisacs0",
        "/sys/class/net/aegisacs1", "/sys/class/net/aegisacp0",
        "/sys/class/net/aegisacp1", "/sys/class/net/aegis-tun0",
    ):
        target = Path(path)
        need(not target.exists() and not target.is_symlink())
    for family in ("-4", "-6"):
        routes = strict_json(call_output(
            ["/usr/sbin/ip", "-j", family, "route", "show", "table", "all"],
            maximum=1 << 20, timeout=5))
        need(type(routes) is list)
        for route in routes:
            need(type(route) is dict and route.get("dev") != "aegis-tun0" and
                 route.get("dst") not in ("::/1", "8000::/1"))
        rules = strict_json(call_output(
            ["/usr/sbin/ip", "-j", family, "rule", "show"],
            maximum=1 << 20, timeout=5))
        need(type(rules) is list)
        for rule in rules:
            need(type(rule) is dict and rule.get("table") not in (100, "100"))


def _abort_topology_absent():
    for path in ("/sys/class/net/aegisaw0", "/run/netns/aegisaw-sink",
                 "/run/aegis-auto-topology/owned-state.json",
                 "/run/aegis-auto-topology/authority.sock"):
        target = Path(path)
        need(not target.exists() and not target.is_symlink())


def _abort_route_hashes():
    hashes = []
    for family in ("-4", "-6"):
        raw = call_output(["/usr/sbin/ip", "-j", family, "route", "show",
                           "table", "all"], maximum=1 << 20, timeout=5)
        routes = strict_json(raw)
        need(type(routes) is list)
        # iproute2 reports the remaining RA lifetime as a decreasing integer.
        # Keep the field present and bind every other route attribute exactly.
        for route in routes:
            need(type(route) is dict)
            if "expires" in route:
                need(type(route["expires"]) is int and route["expires"] >= 0)
                route["expires"] = 0
        canonical = json.dumps(routes, sort_keys=True,
                               separators=(",", ":")).encode()
        hashes.append(hashlib.sha256(canonical).hexdigest())
    return hashes


def _abort_unit_barrier(*, allow_active):
    jobs = call_output(["/usr/bin/systemctl", "list-jobs", "--plain",
                        "--no-legend", "--no-pager"], maximum=65536,
                       timeout=5).decode("ascii")
    need(not any("aegis-" in line for line in jobs.splitlines()))
    _abort_unit_quiescent("aegis-client.service")
    for unit in FRESH_CLIENT_UNITS:
        if unit in {item[0] for item in PASSIVE_ACTORS}:
            continue
        _abort_unit_quiescent(unit)
    _abort_unit_quiescent("aegis-device-egress-guard.service")
    return _abort_actor_states(allow_active=allow_active)


def _abort_rolled_stage_tree(root):
    """Bind every private stage inode; zero-byte lock files are intentional."""
    root = absolute(str(root))
    entries = []
    total = 0

    def walk(path, relative):
        nonlocal total
        before = path.lstat()
        need(before.st_uid == before.st_gid == 0 and before.st_nlink >= 1 and
             not stat.S_IMODE(before.st_mode) & 0o022 and
             len(entries) < PASSIVE_ABORT_STAGE_ENTRIES)
        row = {"path": relative, "dev": before.st_dev, "ino": before.st_ino,
               "mode": before.st_mode, "uid": before.st_uid, "gid": before.st_gid,
               "nlink": before.st_nlink, "size": before.st_size,
               "mtime_ns": before.st_mtime_ns}
        entries.append(row)
        if stat.S_ISDIR(before.st_mode):
            need(stat.S_IMODE(before.st_mode) == 0o700)
            fd = directory(path, 0o700)
            try:
                names = sorted(os.listdir(fd))
                need(len(names) <= PASSIVE_ABORT_STAGE_ENTRIES and all(
                    re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", name) and
                    name not in (".", "..") for name in names))
                for name in names:
                    walk(path / name, name if relative == "." else relative + "/" + name)
            finally:
                os.close(fd)
        else:
            need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and
                 stat.S_IMODE(before.st_mode) == 0o600 and
                 before.st_size <= PASSIVE_FILE_MAX)
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK |
                         os.O_CLOEXEC)
            try:
                opened = os.fstat(fd)
                need(stat.S_ISREG(opened.st_mode) and opened.st_nlink == 1 and
                     opened.st_uid == opened.st_gid == 0 and
                     stat.S_IMODE(opened.st_mode) == 0o600 and
                     (opened.st_dev, opened.st_ino, opened.st_size) ==
                     (before.st_dev, before.st_ino, before.st_size))
                digest = hashlib.sha256()
                size = 0
                while chunk := os.read(fd, 65536):
                    size += len(chunk)
                    need(size <= PASSIVE_FILE_MAX)
                    digest.update(chunk)
                sha = digest.hexdigest()
                checked = os.fstat(fd)
                need((checked.st_dev, checked.st_ino, checked.st_size,
                      checked.st_mtime_ns) ==
                     (opened.st_dev, opened.st_ino, opened.st_size,
                      opened.st_mtime_ns))
            finally:
                os.close(fd)
            need(size == before.st_size)
            total += size
            need(total <= PASSIVE_ABORT_STAGE_MAX)
            row["sha256"] = sha
        after = path.lstat()
        need(all(getattr(before, field) == getattr(after, field) for field in
                 ("st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_nlink",
                  "st_size", "st_mtime_ns")))

    walk(root, ".")
    need({".publication-fence.lock", ".stage-mutation.lock"} <=
         {entry["path"] for entry in entries})
    return entries


def _abort_rolled_probe(install_fd):
    """Use the retained new binary's read-only inherited-lock certificate."""
    fresh_package_lock(install_fd)
    parent = directory(PASSIVE_ABORT_STAGE_PARENT)
    try:
        names = os.listdir(parent)
        need(len(names) == 1 and re.fullmatch(r"\.auto-[0-9a-f]{32}", names[0]))
        stage = PASSIVE_ABORT_STAGE_PARENT / names[0]
    finally:
        os.close(parent)
    control = _passive_control()
    try:
        names = os.listdir(control)
        archives = [name for name in names if re.fullmatch(
            r"archived-[0-9a-f]{32}\.json", name)]
        need(len(archives) == 1)
        pointer = archives[0]
        raw = bounded_root_bytes(CONTROL / pointer, 8192, (0o600,))
        previous = strict_json(raw)
        need(type(previous) is dict and previous.get("status") == "pending" and
             previous.get("stage") == str(stage) and
             type(previous.get("previous_binary")) is dict and
             previous["previous_binary"].get("sha256") ==
             previous.get("candidate_sha256"))
        failures = [name for name in names if name.startswith("failure-")]
        extras = set(names) - {PASSIVE_INTENT, PASSIVE_INPUT, PASSIVE_READY,
                               "v2-enabled", *failures}
        need(pointer in extras and len(extras) <= 6 and all(
            name == pointer or re.fullmatch(r"backup-[0-9a-f]{32}\.bin", name) or
            re.fullmatch(r"prepare-archive-[0-9a-f]{64}\.json", name)
            for name in extras))
        need(previous["previous_binary"]["name"] in extras)
    finally:
        os.close(control)
    verifier_root = Path(__file__).resolve().parents[2]
    need(verifier_root.parent == Path("/var/lib/aegis-auto/releases"))
    signed_client_package(verifier_root)
    proof = strict_json(call_output(
        [str(verifier_root / "bin/aegis-client"), "auto-verify-fresh-rolled-back",
         str(stage), pointer, "--lock-fd", str(install_fd)],
        maximum=8192, timeout=30, pass_fds=(install_fd,)))
    need(type(proof) is dict and set(proof) == {
        "schema", "stage", "stage_device", "stage_inode", "candidate_sha256",
        "pointer_archive", "pointer_sha256", "fresh_intent_sha256",
        "public_payload_root", "old_unit_roles_sha256"} and
         proof["schema"] == "aegis_auto_v2_fresh_rolled_back_proof_v1" and
         proof["stage"] == str(stage) and proof["pointer_archive"] == pointer and
         proof["pointer_sha256"] == hashlib.sha256(raw).hexdigest() and
         proof["candidate_sha256"] == previous["candidate_sha256"] and
         type(proof["stage_device"]) is int and
         type(proof["stage_inode"]) is int and
         all(type(proof[key]) is str and re.fullmatch(r"[0-9a-f]{64}", proof[key])
             for key in ("candidate_sha256", "pointer_sha256", "fresh_intent_sha256",
                         "old_unit_roles_sha256")))
    root_fd = directory(stage, 0o700)
    try:
        named = os.fstat(root_fd)
        need((named.st_dev, named.st_ino) ==
             (proof["stage_device"], proof["stage_inode"]))
    finally:
        os.close(root_fd)
    tree = _abort_rolled_stage_tree(stage)
    return {"proof": proof, "stage": str(stage), "tree": tree,
            "control_leaves": sorted(extras)}


def _abort_rolled_stage_location(value):
    original = Path(value["stage"])
    retired = Path(value["retired_path"])
    original_present = original.exists() or original.is_symlink()
    retired_present = retired.exists() or retired.is_symlink()
    need(original_present != retired_present)
    parent = directory(PASSIVE_ABORT_STAGE_PARENT)
    try:
        need(set(os.listdir(parent)) == ({original.name} if original_present else set()))
    finally:
        os.close(parent)
    path = original if original_present else retired
    held = directory(path, 0o700)
    try:
        info = os.fstat(held)
        need((info.st_dev, info.st_ino) ==
             (value["proof"]["stage_device"], value["proof"]["stage_inode"]))
    finally:
        os.close(held)
    need(_abort_rolled_stage_tree(path) == value["tree"])
    return path, original_present


def _abort_rolled_stage_fences(path):
    """Acquire the product's exact publication→mutation→root order, nonblocking."""
    held = []
    try:
        for name in (".publication-fence.lock", ".stage-mutation.lock"):
            fd = os.open(path / name, os.O_RDONLY | os.O_NOFOLLOW |
                         os.O_NONBLOCK | os.O_CLOEXEC)
            held.append(fd)
            info = os.fstat(fd)
            named = (path / name).lstat()
            need(stat.S_ISREG(info.st_mode) and info.st_uid == info.st_gid == 0 and
                 info.st_nlink == 1 and stat.S_IMODE(info.st_mode) == 0o600 and
                 info.st_size == 0 and (info.st_dev, info.st_ino) ==
                 (named.st_dev, named.st_ino))
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        fd = directory(path, 0o700)
        held.append(fd)
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        _abort_rolled_fences_revalidate(path, held)
        return held
    except BaseException:
        for fd in reversed(held):
            os.close(fd)
        raise


def _abort_rolled_fences_revalidate(path, held):
    need(len(held) == 3)
    for name, fd in zip((".publication-fence.lock", ".stage-mutation.lock"),
                        held[:2]):
        opened = os.fstat(fd)
        named = (path / name).lstat()
        need((opened.st_dev, opened.st_ino, opened.st_mode, opened.st_uid,
              opened.st_gid, opened.st_nlink) ==
             (named.st_dev, named.st_ino, named.st_mode, named.st_uid,
              named.st_gid, named.st_nlink))
    opened = os.fstat(held[2])
    named = path.lstat()
    need((opened.st_dev, opened.st_ino, opened.st_mode, opened.st_uid,
          opened.st_gid) ==
         (named.st_dev, named.st_ino, named.st_mode, named.st_uid,
          named.st_gid))


def _abort_rolled_copy_file(source, target, expected, deadline):
    source_fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK |
                        os.O_CLOEXEC)
    try:
        source_info = os.fstat(source_fd)
        need(stat.S_ISREG(source_info.st_mode) and
             (source_info.st_dev, source_info.st_ino, source_info.st_size) ==
             (expected["dev"], expected["ino"], expected["size"]))
        try:
            target_fd = os.open(target, os.O_RDWR | os.O_CREAT | os.O_EXCL |
                                os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, 0o600)
        except FileExistsError:
            target_fd = os.open(target, os.O_RDWR | os.O_NOFOLLOW |
                                os.O_NONBLOCK | os.O_CLOEXEC)
        try:
            target_info = os.fstat(target_fd)
            need(stat.S_ISREG(target_info.st_mode) and target_info.st_uid ==
                 target_info.st_gid == 0 and target_info.st_nlink == 1 and
                 stat.S_IMODE(target_info.st_mode) == 0o600 and
                 target_info.st_size <= expected["size"])
            # A crash may leave an exact prefix. Compare it with the still
            # fenced source inode before resuming; never replace a foreign file.
            remaining = target_info.st_size
            while remaining:
                need(time.monotonic() < deadline)
                left = os.read(source_fd, min(65536, remaining))
                right = os.read(target_fd, len(left))
                need(left and left == right)
                remaining -= len(left)
            os.lseek(target_fd, 0, os.SEEK_END)
            copied = target_info.st_size
            while copied < expected["size"]:
                need(time.monotonic() < deadline)
                chunk = os.read(source_fd, min(65536, expected["size"] - copied))
                need(chunk)
                view = memoryview(chunk)
                while view:
                    count = os.write(target_fd, view)
                    need(count > 0)
                    view = view[count:]
                copied += len(chunk)
            os.fsync(target_fd)
            os.lseek(target_fd, 0, os.SEEK_SET)
            digest = hashlib.sha256()
            length = 0
            while chunk := os.read(target_fd, 65536):
                need(time.monotonic() < deadline)
                length += len(chunk)
                need(length <= expected["size"])
                digest.update(chunk)
            need(length == expected["size"] and
                 digest.hexdigest() == expected["sha256"])
        finally:
            os.close(target_fd)
    finally:
        os.close(source_fd)


def _abort_rolled_copy_stage(archive, value, path):
    deadline = time.monotonic() + PASSIVE_ABORT_COPY_SECONDS
    destination = archive / "stage-copy"
    if not destination.exists() and not destination.is_symlink():
        archive_fd = _abort_archive_dir(archive)
        try:
            os.mkdir("stage-copy", 0o700, dir_fd=archive_fd)
            os.fsync(archive_fd)
        finally:
            os.close(archive_fd)
    copied = directory(destination, 0o700)
    os.close(copied)
    expected = {entry["path"]: entry for entry in value["tree"]}
    need(len(expected) == len(value["tree"]))
    # Refuse unknown destination names before continuing a partial copy.
    for folder, dirs, files in os.walk(destination, followlinks=False):
        relative = Path(folder).relative_to(destination)
        for name in dirs + files:
            name_path = str(relative / name) if relative != Path(".") else name
            need(name_path in expected and
                 re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", name))
    for entry in value["tree"][1:]:
        need(time.monotonic() < deadline)
        relative = entry["path"]
        source = path / relative
        target = destination / relative
        if stat.S_ISDIR(entry["mode"]):
            if not target.exists() and not target.is_symlink():
                parent = directory(target.parent, 0o700)
                try:
                    os.mkdir(target.name, 0o700, dir_fd=parent)
                    os.fsync(parent)
                finally:
                    os.close(parent)
            held = directory(target, 0o700)
            os.close(held)
        else:
            parent = directory(target.parent, 0o700)
            try:
                _abort_rolled_copy_file(source, target, entry, deadline)
                os.fsync(parent)
            finally:
                os.close(parent)
    actual = _abort_rolled_stage_tree(destination)
    need(_abort_rolled_copy_rows(actual) ==
         _abort_rolled_copy_rows(value["tree"]))
    receipt = {"schema": "aegis_auto_v2_fresh_rolled_back_stage_copy_v1",
               "stage_device": value["proof"]["stage_device"],
               "stage_inode": value["proof"]["stage_inode"],
               "tree_sha256": hashlib.sha256(json.dumps(value["tree"],
                   sort_keys=True, separators=(",", ":")).encode()).hexdigest()}
    complete = archive / "stage-copy-complete.json"
    if complete.exists() or complete.is_symlink():
        need(strict_json(bounded_root_bytes(complete, 16384, (0o600,))) == receipt)
    else:
        archive_fd = _abort_archive_dir(archive)
        try:
            _passive_write(archive_fd, complete.name, receipt)
        finally:
            os.close(archive_fd)


def _abort_rolled_copy_rows(tree):
    """Directory sizes are filesystem-specific; file bytes and roster are not."""
    return [(row["path"], row["mode"] & 0o170000,
             row["size"] if stat.S_ISREG(row["mode"]) else None,
             row.get("sha256")) for row in tree]


def _abort_rolled_complete_readback(archive, value, *, plan_boot):
    original_present = Path(value["stage"]).exists() or Path(value["stage"]).is_symlink()
    retired_present = (Path(value["retired_path"]).exists() or
                       Path(value["retired_path"]).is_symlink())
    need(not original_present)
    if retired_present:
        retired, original = _abort_rolled_stage_location(value)
        need(not original and retired == Path(value["retired_path"]))
    else:
        # A tmpfs retirement disappears on reboot. The complete durable copy
        # and pending plan still own the transaction; same-boot absence refuses.
        need(plan_boot != current_boot())
        if PASSIVE_ABORT_STAGE_PARENT.exists() or PASSIVE_ABORT_STAGE_PARENT.is_symlink():
            parent = directory(PASSIVE_ABORT_STAGE_PARENT)
            try:
                need(not os.listdir(parent))
            finally:
                os.close(parent)
    copied = _abort_rolled_stage_tree(archive / "stage-copy")
    need(_abort_rolled_copy_rows(copied) ==
         _abort_rolled_copy_rows(value["tree"]))
    expected = {"schema": "aegis_auto_v2_fresh_rolled_back_stage_copy_v1",
                "stage_device": value["proof"]["stage_device"],
                "stage_inode": value["proof"]["stage_inode"],
                "tree_sha256": hashlib.sha256(json.dumps(value["tree"],
                    sort_keys=True, separators=(",", ":")).encode()).hexdigest()}
    need(strict_json(bounded_root_bytes(archive / "stage-copy-complete.json",
                                        16384, (0o600,))) == expected)


def _abort_rolled_retire_stage(archive, plan, install_fd):
    value = plan["recovered"]
    if (plan["boot_id"] != current_boot() and
            not Path(value["stage"]).exists() and
            not Path(value["stage"]).is_symlink() and
            not Path(value["retired_path"]).exists() and
            not Path(value["retired_path"]).is_symlink()):
        _abort_rolled_complete_readback(archive, value, plan_boot=plan["boot_id"])
        return
    path, at_original = _abort_rolled_stage_location(value)
    fences = _abort_rolled_stage_fences(path)
    try:
        fresh_package_lock(install_fd)
        _abort_rolled_fences_revalidate(path, fences)
        _abort_item_location(archive, plan["items"][-1])
        need(_abort_rolled_stage_tree(path) == value["tree"])
        _abort_no_effects(recovered_stage=path if at_original else None)
        _abort_rolled_copy_stage(archive, value, path)
        _abort_rolled_fences_revalidate(path, fences)
        if at_original:
            parent = directory(PASSIVE_ABORT_RETIRED_STAGES.parent)
            try:
                try:
                    os.mkdir(PASSIVE_ABORT_RETIRED_STAGES.name, 0o700,
                             dir_fd=parent)
                    os.fsync(parent)
                except FileExistsError:
                    pass
            finally:
                os.close(parent)
            source_parent = directory(PASSIVE_ABORT_STAGE_PARENT)
            target_parent = directory(PASSIVE_ABORT_RETIRED_STAGES, 0o700)
            try:
                need(os.fstat(source_parent).st_dev == os.fstat(target_parent).st_dev)
                libc = ctypes.CDLL(None, use_errno=True)
                rename = libc.renameat2
                rename.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int,
                                   ctypes.c_char_p, ctypes.c_uint)
                rename.restype = ctypes.c_int
                if rename(source_parent, path.name.encode(), target_parent,
                          Path(value["retired_path"]).name.encode(), 1) != 0:
                    error = ctypes.get_errno()
                    raise OSError(error, os.strerror(error))
                os.fsync(source_parent)
                os.fsync(target_parent)
            finally:
                os.close(target_parent)
                os.close(source_parent)
        retired, original = _abort_rolled_stage_location(value)
        need(not original and retired == Path(value["retired_path"]))
        _abort_rolled_complete_readback(archive, value, plan_boot=plan["boot_id"])
    finally:
        for fd in reversed(fences):
            os.close(fd)


def _abort_plan_items(actors, run_id, *, recovered=False):
    paths = ([Path("/usr/local/lib/aegis/helpers") / leaf
              for leaf in FRESH_CLIENT_HELPERS] +
             [Path("/etc/systemd/system") / leaf for leaf in FRESH_CLIENT_UNITS] +
             [Path("/var/lib/aegis-install/client/auto-guardian-install.json")])
    need(len(paths) == len(set(paths)))
    items = [{"path": str(path), "archive_leaf": f"asset-{index:03d}",
              "tree": _abort_private_tree(path)} for index, path in enumerate(paths)]
    witness = next(item for item in actors if item["unit"] ==
                   "aegis-auto-witness-topology.service")
    socket = PASSIVE_ABORT_WITNESS_SOCKET
    present = socket.exists() or socket.is_symlink()
    if witness["active"]:
        need(present)
        metadata = _abort_socket_metadata(socket)
    elif present:
        metadata = _abort_stale_witness_socket()
    else:
        metadata = None
    socket_archive = socket.parent / ("abort-" + run_id)
    items.append({"path": str(socket), "archive_leaf": f"asset-{len(items):03d}",
                  "archive_path": str(socket_archive / f"asset-{len(items):03d}"),
                  "socket": {"initial_active": witness["active"],
                             "metadata": metadata}})
    for path in (Path("/etc/systemd/system/aegis-client.service.d"), CONTROL):
        item = {"path": str(path), "archive_leaf": f"asset-{len(items):03d}",
                "tree": _abort_private_tree(path, file_max=(256 << 20 if
                         recovered and path == CONTROL else PASSIVE_FILE_MAX))}
        if recovered and path == CONTROL:
            item["file_max"] = 256 << 20
        items.append(item)
    return items


def _abort_archive_dir(path):
    fd = directory(path, 0o700)
    return fd


def _abort_plan_read(archive):
    plan = strict_json(bounded_root_bytes(archive / "plan.json", 1 << 20, (0o600,)))
    need(type(plan) is dict)
    recovered = plan.get("schema") == "aegis_auto_v2_fresh_rolled_back_abort_v1"
    expected_keys = {"schema", "run_id", "boot_id", "source", "intent_sha256",
                     "items", "initial_actors", "failure_count"}
    if recovered:
        expected_keys |= {"recovered"}
    need(set(plan) == expected_keys and
         plan["schema"] in ("aegis_auto_v2_fresh_passive_abort_v1",
                            "aegis_auto_v2_fresh_rolled_back_abort_v1") and
         re.fullmatch(r"[0-9a-f]{32}", plan["run_id"]) and
         archive.name == "abort-" + plan["run_id"] and
         type(plan["items"]) is list and len(plan["items"]) ==
         len(FRESH_CLIENT_HELPERS) + len(FRESH_CLIENT_UNITS) + 4 and
         type(plan["boot_id"]) is str and
         re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}",
                      plan["boot_id"]))
    if recovered:
        value = plan["recovered"]
        need(type(value) is dict and set(value) == {"proof", "stage", "tree",
                                                   "control_leaves", "retired_path"} and
             type(value["proof"]) is dict and
             value["proof"].get("schema") ==
             "aegis_auto_v2_fresh_rolled_back_proof_v1" and
             value["proof"].get("stage") == value["stage"] and
             type(value["stage"]) is str and
             Path(value["stage"]).parent == PASSIVE_ABORT_STAGE_PARENT and
             re.fullmatch(r"\.auto-[0-9a-f]{32}", Path(value["stage"]).name) and
             value["retired_path"] == str(PASSIVE_ABORT_RETIRED_STAGES /
                                          plan["run_id"]) and
             type(value["tree"]) is list and 1 <= len(value["tree"]) <=
             PASSIVE_ABORT_STAGE_ENTRIES and type(value["control_leaves"]) is list and
             len(value["control_leaves"]) <= 6 and
             all(type(name) is str for name in value["control_leaves"]) and
             value["proof"].get("candidate_sha256") ==
             plan["source"].get("candidate_sha256") and
             value["proof"].get("fresh_intent_sha256") == plan["intent_sha256"])
    expected = ([Path("/usr/local/lib/aegis/helpers") / leaf
                 for leaf in FRESH_CLIENT_HELPERS] +
                [Path("/etc/systemd/system") / leaf for leaf in FRESH_CLIENT_UNITS] +
                [Path("/var/lib/aegis-install/client/auto-guardian-install.json"),
                 PASSIVE_ABORT_WITNESS_SOCKET,
                 Path("/etc/systemd/system/aegis-client.service.d"), CONTROL])
    for index, (item, path) in enumerate(zip(plan["items"], expected)):
        keys = ({"path", "archive_leaf", "archive_path", "socket"} if
                path == PASSIVE_ABORT_WITNESS_SOCKET else
                {"path", "archive_leaf", "tree"})
        if recovered and path == CONTROL:
            keys |= {"file_max"}
        need(type(item) is dict and set(item) == keys and
             item["path"] == str(path) and
             item["archive_leaf"] == f"asset-{index:03d}")
        if path != PASSIVE_ABORT_WITNESS_SOCKET:
            need(type(item["tree"]) is list and item["tree"])
            if recovered and path == CONTROL:
                need(item["file_max"] == 256 << 20)
        else:
            need(item["archive_path"] == str(
                PASSIVE_ABORT_WITNESS_SOCKET.parent / ("abort-" + plan["run_id"]) /
                item["archive_leaf"]))
    return plan


def _abort_item_location(archive, item, *, allow_bound=False):
    source = Path(item["path"])
    target = (Path(item["archive_path"]) if "socket" in item else
              archive / item["archive_leaf"])
    source_exists = source.exists() or source.is_symlink()
    target_exists = target.exists() or target.is_symlink()
    if "socket" in item:
        socket = item["socket"]
        need(type(socket) is dict and set(socket) == {"initial_active", "metadata"} and
             type(socket["initial_active"]) is bool and
             (socket["metadata"] is None or type(socket["metadata"]) is dict))
        need(not (source_exists and target_exists))
        if not source_exists and not target_exists:
            need(socket["metadata"] is None or socket["initial_active"] or
                 _abort_plan_read(archive)["boot_id"] != current_boot())
            return False
        need(socket["metadata"] is not None)
        held = source if source_exists else target
        need(_abort_socket_metadata(held) == socket["metadata"])
        if source_exists and not allow_bound:
            need(_abort_stale_witness_socket() == socket["metadata"])
        if target_exists:
            # A renamed AF_UNIX pathname may still have a live listener.  A
            # socket inode in the archive is evidence, never a live authority.
            with open("/proc/net/unix", "rb", buffering=0) as handle:
                table = read_unix_table(handle)
            need(not unix_table_socket_inodes(table, source) and
                 not unix_table_socket_inodes(table, target))
        return source_exists
    need(source_exists != target_exists)
    held = source if source_exists else target
    need(_abort_private_tree(held, file_max=item.get("file_max", PASSIVE_FILE_MAX)) ==
         item["tree"])
    return source_exists


def _abort_move(archive, item):
    if not _abort_item_location(archive, item):
        return
    source = Path(item["path"])
    target = (Path(item["archive_path"]) if "socket" in item else
              archive / item["archive_leaf"])
    source_parent = directory(source.parent)
    if "socket" in item and not target.parent.exists():
        os.mkdir(target.parent.name, 0o700, dir_fd=source_parent)
        os.fsync(source_parent)
    archive_fd = directory(target.parent, 0o700)
    try:
        need(os.fstat(source_parent).st_dev == os.fstat(archive_fd).st_dev)
        os.rename(source.name, target.name, src_dir_fd=source_parent,
                  dst_dir_fd=archive_fd)
        os.fsync(source_parent)
        os.fsync(archive_fd)
    finally:
        os.close(archive_fd)
        os.close(source_parent)
    need(not _abort_item_location(archive, item))


def _abort_pending_plan():
    raw = bounded_root_bytes(PASSIVE_ABORT_PENDING, 16384, (0o600,))
    pointer = strict_json(raw)
    need(type(pointer) is dict and set(pointer) == {"schema", "run_id", "plan_sha256"} and
         pointer["schema"] == "aegis_auto_v2_fresh_passive_abort_pending_v1" and
         type(pointer["run_id"]) is str and
         re.fullmatch(r"[0-9a-f]{32}", pointer["run_id"]) and
         type(pointer["plan_sha256"]) is str and
         re.fullmatch(r"[0-9a-f]{64}", pointer["plan_sha256"]))
    archive = PASSIVE_ABORT_ARCHIVES / ("abort-" + pointer["run_id"])
    fd = _abort_archive_dir(archive)
    os.close(fd)
    plan_raw = bounded_root_bytes(archive / "plan.json", 1 << 20, (0o600,))
    need(hashlib.sha256(plan_raw).hexdigest() == pointer["plan_sha256"])
    return archive, _abort_plan_read(archive)


def _abort_completed_plan(install_fd):
    """Read back one completed abort after a crash following the final rename."""
    if CONTROL.exists() or CONTROL.is_symlink():
        return None
    if not PASSIVE_ABORT_ARCHIVES.exists() and not PASSIVE_ABORT_ARCHIVES.is_symlink():
        return None
    archive_fd = directory(PASSIVE_ABORT_ARCHIVES, 0o700)
    try:
        names = sorted(os.listdir(archive_fd))
        need(len(names) <= 32 and all(re.fullmatch(r"abort-[0-9a-f]{32}", name)
                                       for name in names))
    finally:
        os.close(archive_fd)
    candidates = []
    for name in names:
        archive = PASSIVE_ABORT_ARCHIVES / name
        completed = archive / "completed.json"
        if not completed.exists() and not completed.is_symlink():
            continue
        pointer = strict_json(bounded_root_bytes(completed, 16384, (0o600,)))
        plan_raw = bounded_root_bytes(archive / "plan.json", 1 << 20, (0o600,))
        need(type(pointer) is dict and set(pointer) == {"schema", "run_id",
                                                   "plan_sha256"} and
             pointer["schema"] == "aegis_auto_v2_fresh_passive_abort_pending_v1" and
             pointer["run_id"] == name[6:] and
             pointer["plan_sha256"] == hashlib.sha256(plan_raw).hexdigest())
        plan = _abort_plan_read(archive)
        if (_passive_identity(plan["source"]["public_payload_root"], "packaged") ==
                plan["source"]):
            candidates.append((archive, plan))
    need(len(candidates) <= 1)
    if not candidates:
        return None
    archive, plan = candidates[0]
    _passive_installed_origin(plan["source"], install_fd)
    need(all(not _abort_item_location(archive, item) for item in plan["items"]))
    if "recovered" in plan:
        _abort_rolled_complete_readback(archive, plan["recovered"],
                                        plan_boot=plan["boot_id"])
    _abort_unit_barrier(allow_active=False)
    _abort_no_effects()
    _abort_topology_absent()
    return archive, plan


def _aborted_package_requires_reapply(install_fd):
    """Recognize only an authenticated completed abort with its assets retired.

    An exact package reapply restores the helper roster and keeps ordinary
    dpkg verification authoritative. No archive bytes are removed here.
    """
    if not (PASSIVE_ABORT_ARCHIVES.exists() or PASSIVE_ABORT_ARCHIVES.is_symlink()):
        return False
    for name in FRESH_CLIENT_HELPERS:
        path = Path('/usr/local/lib/aegis/helpers') / name
        if path.exists() or path.is_symlink():
            return False
    return _abort_completed_plan(install_fd) is not None


def _abort_publish_intent(install_fd):
    stage_present = False
    if PASSIVE_ABORT_STAGE_PARENT.exists() or PASSIVE_ABORT_STAGE_PARENT.is_symlink():
        stage_fd = directory(PASSIVE_ABORT_STAGE_PARENT)
        try:
            stage_present = bool(os.listdir(stage_fd))
        finally:
            os.close(stage_fd)
    if stage_present:
        return _abort_publish_rolled_intent(install_fd)
    intent, evidence = _abort_original_facts(install_fd)
    actors = _abort_unit_barrier(allow_active=True)
    _abort_no_effects(allow_actor_processes=True)
    run_id = secrets.token_hex(16)
    parent = directory(PASSIVE_ABORT_PENDING.parent, 0o700)
    try:
        try:
            os.mkdir(PASSIVE_ABORT_ARCHIVES.name, 0o700, dir_fd=parent)
            os.fsync(parent)
        except FileExistsError:
            pass
    finally:
        os.close(parent)
    archives_fd = directory(PASSIVE_ABORT_ARCHIVES, 0o700)
    try:
        os.mkdir("abort-" + run_id, 0o700, dir_fd=archives_fd)
        os.fsync(archives_fd)
    finally:
        os.close(archives_fd)
    archive = PASSIVE_ABORT_ARCHIVES / ("abort-" + run_id)
    archive_fd = _abort_archive_dir(archive)
    try:
        items = _abort_plan_items(actors, run_id)
        archive_dev = os.fstat(archive_fd).st_dev
        for item in items:
            source = Path(item["path"])
            if "socket" in item:
                if item["socket"]["metadata"] is not None:
                    need(source.lstat().st_dev == source.parent.lstat().st_dev)
            else:
                need(source.lstat().st_dev == archive_dev)
        plan = {"schema": "aegis_auto_v2_fresh_passive_abort_v1",
                "run_id": run_id, "boot_id": current_boot(),
                "source": intent["source"],
                "intent_sha256": evidence["intent_sha256"],
                "failure_count": evidence["failure_count"],
                "initial_actors": actors, "items": items}
        plan_raw = (json.dumps(plan, sort_keys=True,
                               separators=(",", ":")) + "\n").encode()
        need(len(plan_raw) <= 1 << 20)
        atomic_exclusive_bytes(archive_fd, "plan.json", plan_raw)
        raw = bounded_root_bytes(archive / "plan.json", 1 << 20, (0o600,))
        need(raw == plan_raw and strict_json(raw) == plan)
        pointer = {"schema": "aegis_auto_v2_fresh_passive_abort_pending_v1",
                   "run_id": run_id, "plan_sha256": hashlib.sha256(raw).hexdigest()}
    finally:
        os.close(archive_fd)
    parent = directory(PASSIVE_ABORT_PENDING.parent, 0o700)
    try:
        fresh_package_lock(install_fd)
        need(not PASSIVE_ABORT_PENDING.exists() and
             not PASSIVE_ABORT_PENDING.is_symlink())
        _passive_write(parent, PASSIVE_ABORT_PENDING.name, pointer)
    finally:
        os.close(parent)
    return _abort_pending_plan()


def _abort_publish_rolled_intent(install_fd):
    recovered = _abort_rolled_probe(install_fd)
    intent, evidence = _abort_original_facts(install_fd, recovered=recovered)
    proof = recovered["proof"]
    need(intent["source"]["candidate_sha256"] == proof["candidate_sha256"] and
         intent["source"]["public_payload_root"] == proof["public_payload_root"] and
         evidence["intent_sha256"] == proof["fresh_intent_sha256"])
    actors = _abort_unit_barrier(allow_active=True)
    _abort_no_effects(allow_actor_processes=True,
                      recovered_stage=recovered["stage"])
    run_id = secrets.token_hex(16)
    recovered["retired_path"] = str(PASSIVE_ABORT_RETIRED_STAGES / run_id)
    parent = directory(PASSIVE_ABORT_PENDING.parent, 0o700)
    try:
        try:
            os.mkdir(PASSIVE_ABORT_ARCHIVES.name, 0o700, dir_fd=parent)
            os.fsync(parent)
        except FileExistsError:
            pass
    finally:
        os.close(parent)
    archives_fd = directory(PASSIVE_ABORT_ARCHIVES, 0o700)
    try:
        os.mkdir("abort-" + run_id, 0o700, dir_fd=archives_fd)
        os.fsync(archives_fd)
    finally:
        os.close(archives_fd)
    archive = PASSIVE_ABORT_ARCHIVES / ("abort-" + run_id)
    archive_fd = _abort_archive_dir(archive)
    try:
        items = _abort_plan_items(actors, run_id, recovered=True)
        archive_dev = os.fstat(archive_fd).st_dev
        for item in items:
            source = Path(item["path"])
            if "socket" in item:
                if item["socket"]["metadata"] is not None:
                    need(source.lstat().st_dev == source.parent.lstat().st_dev)
            else:
                need(source.lstat().st_dev == archive_dev)
        plan = {"schema": "aegis_auto_v2_fresh_rolled_back_abort_v1",
                "run_id": run_id, "boot_id": current_boot(),
                "source": intent["source"], "intent_sha256": evidence["intent_sha256"],
                "failure_count": evidence["failure_count"],
                "initial_actors": actors, "items": items, "recovered": recovered}
        raw = (json.dumps(plan, sort_keys=True,
                          separators=(",", ":")) + "\n").encode()
        need(len(raw) <= 1 << 20)
        atomic_exclusive_bytes(archive_fd, "plan.json", raw)
        need(bounded_root_bytes(archive / "plan.json", 1 << 20, (0o600,)) == raw)
        pointer = {"schema": "aegis_auto_v2_fresh_passive_abort_pending_v1",
                   "run_id": run_id,
                   "plan_sha256": hashlib.sha256(raw).hexdigest()}
    finally:
        os.close(archive_fd)
    parent = directory(PASSIVE_ABORT_PENDING.parent, 0o700)
    try:
        fresh_package_lock(install_fd)
        need(not PASSIVE_ABORT_PENDING.exists() and
             not PASSIVE_ABORT_PENDING.is_symlink())
        _passive_write(parent, PASSIVE_ABORT_PENDING.name, pointer)
    finally:
        os.close(parent)
    return _abort_pending_plan()


def _abort_complete_pointer(archive):
    """One final same-filesystem rename releases the package pending gate."""
    parent = directory(PASSIVE_ABORT_PENDING.parent, 0o700)
    archive_fd = _abort_archive_dir(archive)
    try:
        need(not (archive / "completed.json").exists() and
             not (archive / "completed.json").is_symlink())
        need(os.fstat(parent).st_dev == os.fstat(archive_fd).st_dev)
        os.rename(PASSIVE_ABORT_PENDING.name, "completed.json",
                  src_dir_fd=parent, dst_dir_fd=archive_fd)
        os.fsync(parent)
        os.fsync(archive_fd)
    finally:
        os.close(archive_fd)
        os.close(parent)
    need(not PASSIVE_ABORT_PENDING.exists() and
         not PASSIVE_ABORT_PENDING.is_symlink())


def abort_fresh_passive(install_fd):
    """Retire only a first packaged, never-active fresh A, retaining every byte."""
    need(sys.platform == "linux" and os.geteuid() == 0)
    fresh_package_lock(install_fd)
    if PASSIVE_ABORT_PENDING.exists() or PASSIVE_ABORT_PENDING.is_symlink():
        archive, plan = _abort_pending_plan()
    else:
        completed = _abort_completed_plan(install_fd)
        if completed is not None:
            archive, plan = completed
            return {"status": ("aborted-fresh-rolled-back" if "recovered" in plan else
                               "aborted-fresh-passive"), "run_id": plan["run_id"],
                    "archive": str(archive),
                    "failure_count": plan["failure_count"]}
        archive, plan = _abort_publish_intent(install_fd)
    need(_passive_identity(plan["source"]["public_payload_root"], "packaged") ==
         plan["source"] and plan["source"]["fresh_origin"] == "packaged")
    _passive_installed_origin(plan["source"], install_fd)
    recovered = plan.get("recovered")
    stage_path = None
    if recovered is not None:
        if (plan["boot_id"] != current_boot() and
                not Path(recovered["stage"]).exists() and
                not Path(recovered["retired_path"]).exists()):
            _abort_rolled_complete_readback(archive, recovered,
                                            plan_boot=plan["boot_id"])
        else:
            stage_path, at_original = _abort_rolled_stage_location(recovered)
        need(plan["source"]["candidate_sha256"] ==
             recovered["proof"]["candidate_sha256"] and
             plan["source"]["public_payload_root"] ==
             recovered["proof"]["public_payload_root"] and
             plan["intent_sha256"] ==
             recovered["proof"]["fresh_intent_sha256"])
    # A crash after renaming a unit or the boot-gate drop-in can leave PID 1
    # correctly reporting NeedDaemonReload=yes. Authenticate every on-disk
    # inode and every no-Prepare fact before the bounded reconciliation; the
    # strict PID 1 graph is checked immediately afterwards, before any Stop.
    _abort_no_effects(allow_actor_processes=True,
                      recovered_stage=stage_path if recovered is not None else None)
    first_unit = len(FRESH_CLIENT_HELPERS)
    administrative = (plan["items"][first_unit:first_unit + len(FRESH_CLIENT_UNITS)] +
                      [plan["items"][-2]])
    administrative_locations = [_abort_item_location(archive, item)
                                for item in administrative]
    archived_admin = not all(administrative_locations)
    if archived_admin:
        # A crash can cut between an exact unit/drop-in rename and PID 1's
        # reload. Reconcile only after the archived bytes are reauthenticated.
        call_output(["/usr/bin/systemctl", "daemon-reload"], maximum=1024,
                    timeout=10)
    actors = _abort_unit_barrier(allow_active=True)
    active_witness = any(item["unit"] == "aegis-auto-witness-topology.service" and
                         item["active"] for item in actors)
    locations = [_abort_item_location(archive, item,
                                      allow_bound=active_witness and "socket" in item)
                 for item in plan["items"]]
    # A prior coordinator binary may still be installed after a crash. The
    # sealed CONTROL tree and all external no-Prepare facts are re-admitted
    # before this retry may stop any actor.
    _abort_no_effects(allow_actor_processes=True,
                      recovered_stage=stage_path if recovered is not None else None)
    if plan["boot_id"] != current_boot():
        _abort_unit_barrier(allow_active=False)
        _abort_no_effects(recovered_stage=stage_path if recovered is not None else None)
    _abort_unit_barrier(allow_active=True)
    # Stop the owner first. Each stop uses the package's exact, already verified
    # unit; witness ExecStopPost performs its source-owned route inverse.
    for unit, _socket, _source in PASSIVE_ACTORS:
        facts = _abort_unit_facts(unit)
        if facts["ActiveState"] == "active":
            call_output(["/usr/bin/systemctl", "stop", unit], maximum=1024,
                        timeout=30)
            fresh_package_lock(install_fd)
    _abort_unit_barrier(allow_active=False)
    _abort_no_effects(recovered_stage=stage_path if recovered is not None else None)
    # A stopped witness can retain an interrupted owned topology. Its existing
    # fixed inverse authenticates state, link kind and exact baseline routes.
    inverse = archive / "inverse.json"
    if not inverse.exists() and not inverse.is_symlink():
        witness = Path("/usr/local/lib/aegis/helpers/lib/aegis_auto_witness_topology.py")
        result = strict_json(call_output(["/usr/bin/python3", "-I", "-B",
                                          str(witness), "cleanup"],
                                         maximum=4096, timeout=15))
        need(type(result) is dict and
             result.get("schema") == "aegis_auto_witness_topology_cleanup_v1" and
             result.get("routes_restored") is True)
        archive_fd = _abort_archive_dir(archive)
        try:
            _passive_write(archive_fd, "inverse.json", {
                "schema": "aegis_auto_v2_fresh_passive_abort_inverse_v1",
                "run_id": plan["run_id"], "witness": result,
                "route_hashes": _abort_route_hashes()})
        finally:
            os.close(archive_fd)
    else:
        record = strict_json(bounded_root_bytes(inverse, 16384, (0o600,)))
        need(type(record) is dict and record.get("schema") ==
             "aegis_auto_v2_fresh_passive_abort_inverse_v1" and
             record.get("run_id") == plan["run_id"] and
             type(record.get("witness")) is dict and
             record["witness"].get("routes_restored") is True and
             record.get("route_hashes") == _abort_route_hashes())
    _abort_no_effects(recovered_stage=stage_path if recovered is not None else None)
    if recovered is not None:
        # The whole tmpfs stage is preserved by same-filesystem rename only
        # after its durable cross-filesystem copy is complete. No source leaf
        # is unlinked, including either product lock file.
        _abort_rolled_retire_stage(archive, plan, install_fd)
        stage_path = None
        _abort_no_effects()
    socket_item = next(item for item in plan["items"] if "socket" in item)
    _abort_move(archive, socket_item)
    _abort_topology_absent()
    for item in plan["items"][:-2]:
        fresh_package_lock(install_fd)
        _abort_move(archive, item)
    call_output(["/usr/bin/systemctl", "daemon-reload"], maximum=1024, timeout=10)
    _abort_unit_barrier(allow_active=False)
    # The boot gate is retired only after all autonomous units and client are
    # disabled, inactive, and source helpers/admin units are archived.
    _abort_move(archive, plan["items"][-2])
    call_output(["/usr/bin/systemctl", "daemon-reload"], maximum=1024, timeout=10)
    _abort_unit_barrier(allow_active=False)
    _abort_no_effects()
    fresh_package_lock(install_fd)
    _abort_move(archive, plan["items"][-1])
    need(not CONTROL.exists() and not CONTROL.is_symlink())
    _abort_unit_barrier(allow_active=False)
    _abort_no_source_processes()
    _abort_complete_pointer(archive)
    return {"status": ("aborted-fresh-rolled-back" if recovered is not None else
                       "aborted-fresh-passive"), "run_id": plan["run_id"],
            "archive": str(archive), "failure_count": plan["failure_count"]}


def _abort_failure_diagnostic(error):
    """Fixed, non-sensitive source coordinates for an operator retry."""
    kind = _failure_class(error)
    number = error.errno if isinstance(error, OSError) else 0
    number = number if type(number) is int and 0 <= number <= 4095 else 0
    line = _failure_line(error)
    return {"schema": "aegis_auto_v2_fresh_passive_abort_failure_v1",
            "status": "refused", "class": kind,
            "source": "aegis_installer_auto_v2.py",
            "line": line if 0 <= line <= 10000 else 0,
            "errno": number}


def parser():
    root = argparse.ArgumentParser(add_help=True)
    sub = root.add_subparsers(dest="operation", required=True)
    fresh = sub.add_parser("admit-fresh-package")
    fresh.add_argument("--public-payload-root", required=True)
    fresh.add_argument("--install-fd", type=int, required=True)
    locate = sub.add_parser("passive-locate")
    locate.add_argument("--install-fd", type=int, required=True)
    abort = sub.add_parser("abort-fresh-passive")
    abort.add_argument("--install-fd", type=int, required=True)
    sub.add_parser("passive-retired-readback")
    for command in ("passive-intent", "passive-ready", "passive-actors"):
        passive = sub.add_parser(command)
        passive.add_argument("--install-fd", type=int, required=True)
        passive.add_argument("--public-payload-root", required=True)
        passive.add_argument("--bundle-dir", required=True)
        passive.add_argument("--fresh-origin", choices=("packaged", "source-layout"),
                             required=True)
        for name in PASSIVE_OPTIONS:
            passive.add_argument("--" + name.replace("_", "-"))
    upgrade = sub.add_parser("upgrade-package")
    upgrade.add_argument("--public-payload-root", required=True)
    upgrade.add_argument("--incoming-deb")
    upgrade.add_argument("--requested-mode", choices=("socks-only",))
    cold = sub.add_parser('recover-terminal-migration')
    cold.add_argument('--retained-root', required=True)
    cold.add_argument('--source-fd', type=int, required=True)
    cold.add_argument('--handoff-fd', type=int, required=True)
    cold.add_argument('--stale-rollover', action='store_true')
    package_readback = sub.add_parser('cold-package-readback')
    package_readback.add_argument('--old-root', required=True)
    package_readback.add_argument('--retained-root', required=True)
    package_readback.add_argument('--install-fd',type=int,required=True)
    package_readback.add_argument('--guard-fd',type=int,required=True)
    archive_package=sub.add_parser('cold-archive-package-readback')
    archive_package.add_argument('--old-root',required=True)
    archive_package.add_argument('--retained-root',required=True)
    archive_package.add_argument('--install-fd',type=int,required=True)
    archive_package.add_argument('--guard-fd',type=int,required=True)
    sub.add_parser("stop-current")
    sub.add_parser("uninstall-begin")
    sub.add_parser("uninstall-stop-and-archive")
    sub.add_parser("uninstall-prepare-guard")
    sub.add_parser("uninstall-recover-guard")
    sub.add_parser("uninstall-seal-actors")
    sub.add_parser("uninstall-archive-owners")
    sub.add_parser("uninstall-seal-package-handoff")
    sub.add_parser("uninstall-purge")
    sub.add_parser("uninstall")
    sub.add_parser("boot-current")
    recover = sub.add_parser("recover-current")
    recover.add_argument("--candidate-binary", required=True)
    fresh_recover = sub.add_parser("recover-fresh-prepared")
    fresh_recover.add_argument("--public-payload-root", required=True)
    preflight = sub.add_parser("preflight-passive")
    preflight.add_argument("--candidate-binary", required=True)
    p = sub.add_parser("install")
    for name in ("config-root", "state-dir", "metadata-dir", "staging-parent",
                 "public-payload-root", "candidate-binary", "installed-binary",
                 "runtime-events"):
        p.add_argument("--" + name, required=True)
    p.add_argument("--existing-choice", choices=("none", "upgrade", "reinstall"), required=True)
    p.add_argument("--requested-mode", choices=("socks-only",))
    for name in ("bundle-dir", "masque-server", "masque-ca", "wide-interface",
                 "source-manifest-url", "source-release-channel"):
        p.add_argument("--" + name)
    return root


def _run(args, progress):
    need(sys.platform == "linux" and os.geteuid() == 0)
    paths = {name: absolute(getattr(args, name.replace("-", "_"))) for name in
             ("config-root", "state-dir", "metadata-dir", "staging-parent",
              "public-payload-root", "candidate-binary", "installed-binary", "runtime-events")}
    optional_paths = {name: absolute(value) for name in ("bundle-dir", "masque-ca")
                      if (value := getattr(args, name.replace("-", "_"))) is not None}
    need(args.existing_choice != "reinstall" and
         (args.existing_choice == "none") == ("bundle-dir" in optional_paths))
    need(paths["staging-parent"] == Path("/run/aegis-installer-config-snapshots") and
         paths["installed-binary"] == Path("/usr/local/bin/aegis-client"))
    parent = control_directory()
    try:
        need(current_pointer(parent) is None)
        need(not unsealed_recovery_present(parent))
    finally:
        os.close(parent)
    old_user = pid1_fixed_state()
    guardian_ready(paths["candidate-binary"])
    need(call_line([str(paths["candidate-binary"]), "profile", "auto-config", "protocol"])
         == PROTOCOL.encode())
    prepare = [str(paths["candidate-binary"]), "profile", "auto-config",
               ("prepare-boot-successor" if getattr(args, "_boot_intent_sha256", None)
                else "prepare")]
    for name, value in paths.items():
        prepare.extend(("--" + name, str(value)))
    prepare.extend(("--existing-choice", args.existing_choice, "--udp-carry", "0",
                    "--prepare-handoff", str(PREPARE_HANDOFF)))
    if args.requested_mode is not None:
        prepare.extend(("--requested-mode", args.requested_mode))
    for name, value in optional_paths.items():
        prepare.extend(("--" + name, str(value)))
    for name in ("masque-server", "wide-interface", "source-manifest-url",
                 "source-release-channel"):
        value = getattr(args, name.replace("-", "_"))
        if value is not None:
            prepare.extend(("--" + name, value))
    progress["phase"] = "prepare"
    stage = absolute(call_line(prepare, maximum=4096, timeout=120).decode("ascii"))
    need(stage.parent == paths["staging-parent"])
    # A successful Prepare already owns a protected stage. Publish its recovery
    # pointer before opening the worker: even Ready, inspect or NSS refusal
    # must leave the stage addressable by recover-current. No installed binary
    # is changed by this bookkeeping.
    previous = record_prepared_stage(stage, {**paths, **optional_paths}, args, progress)
    worker = subprocess.Popen([str(paths["candidate-binary"]), "profile", "auto-config",
                               "worker", "--stage", str(stage)], stdin=subprocess.PIPE,
                              stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, close_fds=True)
    started = time.monotonic()
    progress["worker"] = worker
    progress["worker_started"] = started
    terminal = False
    try:
        progress["phase"] = "worker_ready"
        response(fixed_lines(worker, MAX_REPLY, started + PHASE_TIMEOUT), "ready")
        progress["phase"] = "inspect"
        mode = worker_phase(worker, ["inspect", "--field", "product-mode"], started)
        policy = worker_phase(worker, ["inspect", "--field", "runtime-service-policy"], started)
        need(mode in ("socks-only", "wide-redirect-safe", "full-wide-tun") and
             policy in ("root", "dedicated-none", "dedicated-bind"))
        need(args.requested_mode is None or mode == args.requested_mode)
        progress["phase"] = "guardian_mode"
        guardian_ready(paths["candidate-binary"],
                       "passive" if mode == "socks-only" else "guarded")
        new_user = "root" if policy == "root" else "aegis-svc"
        events_path = prepared_runtime_events(
            worker, paths["runtime-events"], new_user, started)
        progress["phase"] = "before_custody"
        worker_phase(worker, ["verify", "--phase", "before-custody"], started)
        need(pid1_fixed_state() == old_user)
        progress["phase"] = "account"
        if new_user == "aegis-svc":
            runtime_account_preflight(paths["state-dir"])
        if new_user == "aegis-svc":
            ensure_runtime_account(paths["state-dir"])
        ensure_runtime_events_directory(events_path, new_user)
        progress["phase"] = "bind_runtime"
        worker_phase(worker, ["bind-runtime-service", "--service-user", new_user], started)
        progress["phase"] = "publish_binary"
        install_candidate(paths["candidate-binary"], paths["installed-binary"], previous)
        for phase, words in (
            ("commit_custody", ["commit-custody", "--service-user", old_user, "--was-active", "0"]),
            ("commit_state", ["commit-state"]), ("commit_config", ["commit-config"]),
            ("seal_receipt", ["seal-install-receipt"]),
            ("publish_policy", ["publish-service-policy"]),
            ("reload_policy", ["reload-service-policy"]),
            ("published_verify", ["verify", "--phase", "published-config"]),
            ("publish_metadata", ["publish-metadata"]),
            ("activation_verify", ["verify", "--phase", "before-activation"]),
        ):
            progress["phase"] = phase
            worker_phase(worker, words, started, phase=phase)
        if mode != "socks-only":
            progress["phase"] = "begin_capture"
            worker_phase(worker, ["begin-capture"], started)
        progress["phase"] = "finalize"
        worker_phase(worker, ["finalize"], started)
        worker.stdin.close()
        need(worker.wait(timeout=5) == 0)
        terminal = True
        installed = os.open(paths["installed-binary"], os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        candidate = os.open(paths["candidate-binary"], os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            need(file_sha(installed) == file_sha(candidate))
        finally:
            os.close(installed)
            os.close(candidate)
        progress["phase"] = "terminal_readback"
        active_after_terminal(stage, mode, paths["installed-binary"])
        progress["phase"] = "generation_seal"
        need(call_output([str(paths["installed-binary"]), "auto-seal-generation",
                          str(stage)], maximum=1024, timeout=30,
                         diagnostic_stderr=True) == b"")
        return True
    finally:
        if not terminal and worker.poll() is None:
            worker.stdin.close()
            try:
                # A closed pipe enters the worker's existing native inverse.
                # StopUnit may use its original 35 s bound; a 5 s supervisor
                # kill would interrupt that proof while the worker holds the
                # sole install lock. This is only a reap bound, not a phase or
                # effect deadline extension.
                worker.wait(timeout=min(90.0, max(0.0, started + WORKER_TIMEOUT - time.monotonic())))
            except subprocess.TimeoutExpired:
                worker.kill()
                worker.wait(timeout=5)
        if worker.stdout:
            worker.stdout.close()



def run(args):
    progress = {"phase": "preflight", "worker": None, "worker_started": None}
    try:
        return _run(args, progress)
    except Exception as error:
        try:
            record_failure(progress, error)
        except Exception:
            pass
        raise


def main(argv=None):
    _set_phase("entry")
    operation = "parse"
    try:
        args = parser().parse_args(argv)
        operation = args.operation
        if operation not in ("uninstall-begin", "uninstall-stop-and-archive",
                             "uninstall-prepare-guard", "uninstall-recover-guard",
                             "uninstall-seal-actors", "uninstall-archive-owners",
                             "uninstall-seal-package-handoff", "uninstall-purge",
                             "uninstall"):
            need(not uninstall_intent_present())
        _set_phase("abort_pending")
        if args.operation not in ("abort-fresh-passive", "recover-fresh-prepared"):
            need(not PASSIVE_ABORT_PENDING.exists() and
                 not PASSIVE_ABORT_PENDING.is_symlink())
        if args.operation == "uninstall-begin":
            print(json.dumps(begin_uninstall(), sort_keys=True, separators=(",", ":")))
            return 0
        if args.operation == "uninstall-stop-and-archive":
            print(json.dumps(uninstall_stop_and_archive(), sort_keys=True,
                             separators=(",", ":")))
            return 0
        if args.operation == "uninstall-prepare-guard":
            print(json.dumps(uninstall_prepare_guard(), sort_keys=True,
                             separators=(",", ":")))
            return 0
        if args.operation == "uninstall-recover-guard":
            print(json.dumps(uninstall_recover_guard(), sort_keys=True,
                             separators=(",", ":")))
            return 0
        if args.operation == "uninstall-seal-actors":
            print(json.dumps(uninstall_seal_actors(), sort_keys=True,
                             separators=(",", ":")))
            return 0
        if args.operation == "uninstall-archive-owners":
            print(json.dumps(uninstall_archive_owners(), sort_keys=True,
                             separators=(",", ":")))
            return 0
        if args.operation == "uninstall-seal-package-handoff":
            print(json.dumps(uninstall_seal_package_handoff(), sort_keys=True,
                             separators=(",", ":")))
            return 0
        if args.operation == "uninstall-purge":
            print(json.dumps(uninstall_purge(), sort_keys=True,
                             separators=(",", ":")))
            return 0
        if args.operation == "uninstall":
            print(json.dumps(uninstall_all(), sort_keys=True,
                             separators=(",", ":")))
            return 0
        if args.operation == "stop-current":
            result = stop_current()
        elif args.operation == "boot-current":
            result = boot_current()
        elif args.operation == 'cold-package-readback':
            print(json.dumps(cold_package_readback(args.old_root,
                args.retained_root,args.install_fd,args.guard_fd),
                sort_keys=True,separators=(',',':')))
        elif args.operation == 'cold-archive-package-readback':
            print(json.dumps(cold_package_readback(args.old_root,
                args.retained_root,args.install_fd,args.guard_fd,
                retained_source=True),sort_keys=True,separators=(',',':')))
            return 0
        elif args.operation == 'recover-terminal-migration':
            if args.stale_rollover:
                result = recover_terminal_rollover(args.retained_root,
                    args.source_fd,args.handoff_fd)
            else:
                result = recover_terminal_migration(args.retained_root,
                    args.source_fd,args.handoff_fd)
        elif args.operation == "upgrade-package":
            result = upgrade_package(args.public_payload_root, args.incoming_deb,
                                     args.requested_mode)
        elif args.operation == "admit-fresh-package":
            result = fresh_installed_package(args.public_payload_root, args.install_fd)
        elif args.operation == "passive-locate":
            result = passive_intent_locate(args.install_fd)
            print(json.dumps(result, separators=(",", ":")))
            return 0
        elif args.operation == "abort-fresh-passive":
            result = abort_fresh_passive(args.install_fd)
            print(json.dumps(result, sort_keys=True, separators=(",", ":")))
            return 0
        elif args.operation == "passive-retired-readback":
            result = _passive_retirement_readback()
            print(json.dumps(result, sort_keys=True, separators=(",", ":")))
            return 0
        elif args.operation in ("passive-intent", "passive-ready", "passive-actors"):
            options = {name: getattr(args, name) for name in PASSIVE_OPTIONS}
            if args.operation == "passive-actors":
                intent = passive_intent_admit(args.public_payload_root, args.bundle_dir,
                                              args.install_fd, options, args.fresh_origin)
                parent = _passive_control()
                try:
                    need(_passive_record(parent, FIRST_ARM_INTENT) is None and
                         _passive_prefix(parent, intent["source"]) == "actors-starting")
                    _, missing = passive_actor_status()
                finally:
                    os.close(parent)
                print(json.dumps({"status": "actors-starting", "missing": missing},
                                 separators=(",", ":")))
                return 0
            result = passive_intent_phase(args.public_payload_root, args.bundle_dir,
                                          args.install_fd, options, args.fresh_origin,
                                          create=args.operation == "passive-intent" and
                                          passive_intent_locate(args.install_fd)["status"] == "absent",
                                          seal_ready=args.operation == "passive-ready")
            print(json.dumps(result, separators=(",", ":")))
            return 0
        elif args.operation == "recover-current":
            result = recover_current(args.candidate_binary)
        elif args.operation == "recover-fresh-prepared":
            result = recover_fresh_prepared(args.public_payload_root)
        elif args.operation == "preflight-passive":
            need(sys.platform == "linux" and os.geteuid() == 0)
            parent = control_directory()
            try:
                need(not unsealed_recovery_present(parent))
            finally:
                os.close(parent)
            guardian_ready(absolute(args.candidate_binary), "passive")
            result = "ready"
        else:
            result = "terminal_active" if run(args) else None
    except Exception as error:
        print(f"AUTO_V2_HELPER_REFUSED operation={operation} phase={_PHASE} "
              f"class={_failure_class(error)} line={_failure_line(error)}", file=sys.stderr)
        if isinstance(error, FreshPassiveAbortedReapplyRequired):
            print("Fresh AUTO preparation was aborted. Reapply the exact client package "
                  "from this administrative bundle, or run the product purge, then retry.",
                  file=sys.stderr)
        if operation == "abort-fresh-passive":
            print(json.dumps(_abort_failure_diagnostic(error), sort_keys=True,
                             separators=(",", ":")))
        elif isinstance(error, FreshPassiveAbortedReapplyRequired):
            print('{"status":"refused","class":"fresh_passive_aborted_reapply_required"}')
        else:
            print('{"status":"refused"}')
        return 1
    print(json.dumps({"status": result}, separators=(",", ":")))
    return 0


def _uninstall_guard_split():
    path = Path("/var/lib/aegis-install/client/device-guard.conf.auto-lease-split")
    if not path.exists() and not path.is_symlink():
        return False
    need(bounded_root_bytes(path, 128, (0o600,)) ==
         b"capture-recovery-in-progress-v1\n")
    return True


def _uninstall_nft_table_absent():
    tables = call_output(["/usr/sbin/nft", "list", "tables"], maximum=16384,
                         timeout=10).decode("ascii", "strict").splitlines()
    need("table inet aegis_device_guard" not in tables)


def _uninstall_unit_state(unit, *, allow_reload_pending=False):
    # Timer units have no process or cgroup properties in systemd's show
    # output. Require their actual schema rather than synthesizing PID facts.
    timer = unit.endswith(".timer")
    fields = (("Id", "LoadState", "ActiveState", "SubState") +
              (() if timer else ("MainPID", "ControlPID", "ControlGroup",
                                  "NFileDescriptorStore")) +
              ("NeedDaemonReload", "FragmentPath"))
    command = ["/usr/bin/systemctl", "show", unit, "--no-pager"]
    for field in fields:
        command.extend(("-p", field))
    lines = call_output(command, maximum=4096, timeout=10).decode("ascii", "strict").splitlines()
    facts = {}
    for line in lines:
        key, sep, value = line.partition("=")
        need(sep and key not in facts)
        facts[key] = value
    need(set(facts) == set(fields) and facts["Id"] == unit and
         facts["LoadState"] in ("loaded", "not-found") and
         facts["NeedDaemonReload"] in (("no", "yes") if allow_reload_pending
                                        else ("no",)))
    return facts


def _uninstall_unit_stopped(unit, *, allow_reload_pending=False):
    facts = _uninstall_unit_state(unit,
        allow_reload_pending=allow_reload_pending)
    need(facts["ActiveState"] == "inactive" and facts["SubState"] == "dead")
    if not unit.endswith(".timer"):
        need(facts["MainPID"] == facts["ControlPID"] == "0" and
             facts["ControlGroup"] == "" and facts["NFileDescriptorStore"] == "0")
    return facts


_UNINSTALL_ACTOR_UNITS = (
    "aegis-auto-config.service", "aegis-auto-guardian.service",
    "aegis-auto-guardian-watchdog.service",
    "aegis-auto-terminal-observer.service",
    "aegis-auto-terminal-transition.service",
    "aegis-auto-capture-topology.service",
    "aegis-auto-witness-topology.service",
    "aegis-auto-trace-rollback-actor.service",
    "aegis-auto-trace-rollback.timer",
    "aegis-auto-trace-rollback.service",
    "aegis-device-dhcp-refresh.service",
    "aegis-device-dhcp-refresh.timer",
)


def _uninstall_no_queued_actor_jobs():
    """Refuse a queued fixed or dynamic actor before replay's daemon reload."""
    jobs = call_output(["/usr/bin/systemctl", "list-jobs", "--no-legend",
                        "--plain"], maximum=65536, timeout=5)
    watched = set(_UNINSTALL_ACTOR_UNITS) | {
        "aegis-client.service", "aegis-device-egress-guard.service",
        "aegis-foreign-policy-monitor.service",
        "aegis-auto-clean-shutdown.service",
        "aegis-device-dhcp-refresh.service",
        "aegis-device-dhcp-refresh.timer"}
    for line in jobs.decode("ascii", "strict").splitlines():
        fields = line.split()
        need(len(fields) >= 2)
        unit = fields[1]
        need(unit not in watched and not unit.startswith((
            "aegis-auto@", "aegis-auto-terminal-a@", "aegis-auto-terminal-b@")))


def _uninstall_terminal_instances_stopped():
    """Admit only quiescent exact A/B instances after the typed private Stop."""
    raw = call_output(["/usr/bin/systemctl", "list-units", "--all", "--plain",
                       "--no-legend", "--no-pager",
                       "aegis-auto-terminal-a@*.service",
                       "aegis-auto-terminal-b@*.service"],
                      maximum=65536, timeout=10)
    units = set()
    for line in raw.decode("ascii", "strict").splitlines():
        parts = line.split()
        need(parts and re.fullmatch(
            r"aegis-auto-terminal-[ab]@[0-9a-f]{64}\.service", parts[0]))
        need(parts[0] not in units)
        units.add(parts[0])
        _uninstall_unit_stopped(parts[0])
    _uninstall_no_queued_actor_jobs()


def _uninstall_reconcile_retired_units(journal_fd, backup_sha):
    """Reconcile a crash between exact unit retirement and PID 1 reload.

    A durable actors-quiescent phase precedes owner retirement. Recheck its
    source identities and the stopped PID 1 graph before reloading changed
    unit files. The regular strict graph is checked again by the caller.
    """
    manifest = uninstall_journal.verify_backup(journal_fd, UNINSTALL_OWNERS,
                                               backup_sha)
    entries = {entry["path"]: entry for entry in manifest["entries"]}
    need(len(entries) == len(manifest["entries"]))
    retired_any = False
    guard_removed = {"aegis-device-egress-guard.service",
                     "aegis-foreign-policy-monitor.service",
                     "aegis-auto-clean-shutdown.service",
                     "aegis-device-dhcp-refresh.service",
                     "aegis-device-dhcp-refresh.timer"}
    for index, owner in enumerate(UNINSTALL_OWNERS[5:], 5):
        expected = entries.get(owner.lstrip("/"))
        need(expected is not None and expected["kind"] in ("absent", "file"))
        retired_path = "/var/lib/aegis-auto-uninstall/backup/retired-%02d" % index
        live = uninstall_journal.source_manifest((owner,))["entries"][0]
        retired = uninstall_journal.source_manifest((retired_path,))["entries"][0]
        need(live["kind"] == "absent" or retired["kind"] == "absent")
        if expected["kind"] == "absent":
            need(live["kind"] == retired["kind"] == "absent")
            continue
        if live["kind"] == retired["kind"] == "absent":
            need(Path(owner).name in guard_removed)
            continue
        actual = retired if retired["kind"] != "absent" else live
        need({key: value for key, value in actual.items() if key != "path"} ==
             {key: value for key, value in expected.items() if key != "path"})
        retired_any |= retired["kind"] != "absent"
    if not retired_any:
        return False
    # A restart after the previous stopped proof may have left an actor or
    # job alive. Never reload its source until a fresh PID 1 readback is clean.
    need(not _uninstall_guard_split())
    _uninstall_nft_table_absent()
    for unit in (*_UNINSTALL_ACTOR_UNITS, "aegis-client.service"):
        facts = _uninstall_unit_stopped(unit, allow_reload_pending=True)
        if facts["LoadState"] == "loaded":
            need(facts["FragmentPath"] == "/etc/systemd/system/" + unit or
                 (unit == "aegis-client.service" and
                  facts["FragmentPath"] == "/usr/lib/systemd/system/" + unit))
        else:
            need(facts["FragmentPath"] == "")
    for unit in ("aegis-device-egress-guard.service",
                 "aegis-foreign-policy-monitor.service",
                 "aegis-auto-clean-shutdown.service",
                 "aegis-device-dhcp-refresh.service",
                 "aegis-device-dhcp-refresh.timer"):
        facts = _uninstall_unit_stopped(unit, allow_reload_pending=True)
        need(facts["LoadState"] == "not-found" and facts["FragmentPath"] == "")
    no_private_jobs_or_units()
    _uninstall_terminal_instances_stopped()
    _uninstall_no_queued_actor_jobs()
    call_output(["/usr/bin/systemctl", "daemon-reload"], maximum=1024,
                timeout=15)
    return True


def _uninstall_stop_actors():
    """Quiesce restart owners while the native deny policy remains armed."""
    # The journal is already durable. Boot-current refuses it; disable the
    # boot trigger before withdrawing an actor's source or guard ownership.
    _uninstall_terminal_instances_stopped()
    units = ("aegis-device-dhcp-refresh.timer",
             "aegis-device-dhcp-refresh.service",
             "aegis-auto-config.service", "aegis-auto-guardian.service",
             "aegis-auto-terminal-observer.service",
             "aegis-auto-terminal-transition.service",
             "aegis-auto-guardian-watchdog.service",
             "aegis-auto-capture-topology.service",
             "aegis-auto-witness-topology.service",
             "aegis-auto-trace-rollback-actor.service",
             "aegis-auto-trace-rollback.timer",
             "aegis-auto-trace-rollback.service")
    for unit in units:
        facts = _uninstall_unit_state(unit)
        if facts["LoadState"] == "loaded":
            need(facts["FragmentPath"] == "/etc/systemd/system/" + unit)
            # Systemd's disable removes only Wants links, not the source unit.
            if unit in ("aegis-device-dhcp-refresh.timer",
                        "aegis-auto-config.service", "aegis-auto-guardian.service",
                        "aegis-auto-witness-topology.service"):
                call_output(["/usr/bin/systemctl", "disable", unit], maximum=2048,
                            timeout=30)
            if facts["ActiveState"] != "inactive":
                call_output(["/usr/bin/systemctl", "stop", unit], maximum=2048,
                            timeout=90)
        _uninstall_unit_stopped(unit)
    no_private_jobs_or_units()
    _uninstall_terminal_instances_stopped()


def uninstall_prepare_guard():
    """Back up exact owners before recover-native may remove guard units."""
    need(sys.platform == "linux" and os.geteuid() == 0)
    lock_fd = _open_original_lock("/run/aegis-auto-install.lock", 9,
                                  allow_uninstall=True, create=True)
    try:
        fd = uninstall_journal.directory()
        try:
            intent, phases = uninstall_journal.read(fd)
            need(len(phases) >= 2 and phases[1][0]["state"] in
                 ("stopped-archived", "reboot-observed"))
            if len(phases) >= 3:
                return {"state": phases[-1][0]["state"], "stage": intent["stage"]}
            _uninstall_terminal_authority_admit()
            backup_sha = uninstall_journal.backup_owners(fd, UNINSTALL_OWNERS)
            split = _uninstall_guard_split()
            guard = _uninstall_owner_fact(
                "/var/lib/aegis-install/client/device-guard.conf")
            observation = hashlib.sha256(uninstall_journal.canonical({
                "backup_manifest_sha256": backup_sha,
                "admitted_guard_sha256": intent["guard_config_sha256"],
                "post_stop_guard": guard,
                "split_present": split})).hexdigest()
            uninstall_journal.advance(fd, "guard-recovering", observation,
                backup_manifest_sha256=backup_sha,
                guard_split_sha256=hashlib.sha256(
                    b"capture-recovery-in-progress-v1\n").hexdigest())
            return {"state": "guard-recovering", "stage": intent["stage"]}
        finally:
            os.close(fd)
    finally:
        os.close(lock_fd)


def uninstall_recover_guard():
    """Resume the guard's own split-marker recovery, then prove native egress."""
    need(sys.platform == "linux" and os.geteuid() == 0)
    fd = uninstall_journal.directory()
    try:
        intent, phases = uninstall_journal.read(fd)
        need(len(phases) >= 3 and phases[2][0]["state"] == "guard-recovering")
        if len(phases) >= 4:
            return {"state": phases[-1][0]["state"], "stage": intent["stage"]}
        _uninstall_guard_split()
        _uninstall_stop_actors()
        state = Path("/var/lib/aegis-install/client/device-guard.conf")
        if state.exists() or state.is_symlink():
            # The installed helper owns the durable split, capture teardown,
            # armed=0 commit, unit removal and nft deletion. Never emulate it.
            helper = Path("/usr/local/lib/aegis/helpers/aegis-device-egress-guard.sh")
            held = held_root_file(helper, 4 << 20, (0o500, 0o555, 0o755))
            os.close(held)
            call_output(["/usr/bin/bash", str(helper), "recover"], maximum=4096,
                        timeout=180, diagnostic_stderr=True)
            raw = bounded_root_bytes(state, 8192, (0o600,))
            need(b"\narmed=0\n" in b"\n" + raw and
                 b"\narmed=1\n" not in b"\n" + raw)
            guard_digest = hashlib.sha256(raw).hexdigest()
        else:
            # SOCKS-only has no device guard; a stray guard unit/table refuses.
            guard_digest = hashlib.sha256(b"guard-absent").hexdigest()
        need(not _uninstall_guard_split())
        for unit in ("aegis-device-egress-guard.service",
                     "aegis-foreign-policy-monitor.service",
                     "aegis-auto-clean-shutdown.service",
                     "aegis-device-dhcp-refresh.service",
                     "aegis-device-dhcp-refresh.timer"):
            facts = _uninstall_unit_stopped(unit)
            need(facts["LoadState"] == "not-found" and facts["FragmentPath"] == "")
        _uninstall_unit_stopped("aegis-client.service")
        _uninstall_nft_table_absent()
        _uninstall_stop_actors()
        uninstall_journal.advance(fd, "guard-released", guard_digest,
            guard_split_sha256=phases[2][0]["guard_split_sha256"])
        return {"state": "guard-released", "stage": intent["stage"]}
    finally:
        os.close(fd)


def uninstall_seal_actors():
    """Record fully quiescent actors only after explicit guard release."""
    need(sys.platform == "linux" and os.geteuid() == 0)
    fd = uninstall_journal.directory()
    try:
        intent, phases = uninstall_journal.read(fd)
        need(len(phases) >= 4 and phases[3][0]["state"] == "guard-released")
        if len(phases) >= 5:
            return {"state": phases[-1][0]["state"], "stage": intent["stage"]}
        _uninstall_stop_actors()
        for unit in ("aegis-auto-capture-topology.service",
                     "aegis-device-egress-guard.service",
                     "aegis-foreign-policy-monitor.service",
                     "aegis-auto-clean-shutdown.service",
                     "aegis-device-dhcp-refresh.service",
                     "aegis-device-dhcp-refresh.timer",
                     "aegis-client.service"):
            _uninstall_unit_stopped(unit)
        need(not _uninstall_guard_split())
        _uninstall_nft_table_absent()
        backup_sha = phases[2][0]["backup_manifest_sha256"]
        uninstall_journal.verify_backup(fd, UNINSTALL_OWNERS, backup_sha)
        observation = hashlib.sha256(uninstall_journal.canonical({
            "units": [*_uninstall_unit_state("aegis-auto-guardian.service").values()],
            "backup_manifest_sha256": backup_sha,
            "guard_release_sha256": phases[3][0]["observation_sha256"]})).hexdigest()
        uninstall_journal.advance(fd, "actors-quiescent", observation,
                                   backup_manifest_sha256=backup_sha)
        return {"state": "actors-quiescent", "stage": intent["stage"]}
    finally:
        os.close(fd)


def uninstall_archive_owners():
    """Retire exact private owners by no-replace rename into backup."""
    need(sys.platform == "linux" and os.geteuid() == 0)
    lock_fd = _open_original_lock("/run/aegis-auto-install.lock", 9,
                                  allow_uninstall=True, create=True)
    try:
        fd = uninstall_journal.directory()
        try:
            intent, phases = uninstall_journal.read(fd)
            need(len(phases) >= 5 and phases[4][0]["state"] == "actors-quiescent")
            if len(phases) >= 6:
                return {"state": phases[-1][0]["state"], "stage": intent["stage"]}
            backup_sha = phases[2][0]["backup_manifest_sha256"]
            _uninstall_reconcile_retired_units(fd, backup_sha)
            _uninstall_stop_actors()
            need(not _uninstall_guard_split())
            _uninstall_nft_table_absent()
            retired_sha = uninstall_journal.retire_owners(fd, UNINSTALL_OWNERS,
                backup_sha, guard_removed=(
                    "/etc/systemd/system/aegis-device-egress-guard.service",
                    "/etc/systemd/system/aegis-foreign-policy-monitor.service",
                    "/etc/systemd/system/aegis-auto-clean-shutdown.service",
                    "/etc/systemd/system/aegis-device-dhcp-refresh.service",
                    "/etc/systemd/system/aegis-device-dhcp-refresh.timer"))
            call_output(["/usr/bin/systemctl", "daemon-reload"], maximum=1024,
                        timeout=15)
            for owner in UNINSTALL_OWNERS[5:]:
                if not _uninstall_owner_is_unit(owner):
                    continue
                facts = _uninstall_unit_stopped(Path(owner).name)
                need(facts["LoadState"] == "not-found" and
                     facts["FragmentPath"] == "")
            _uninstall_unit_stopped("aegis-client.service")
            uninstall_journal.advance(fd, "owners-archived", retired_sha,
                                       backup_manifest_sha256=backup_sha)
            return {"state": "owners-archived", "stage": intent["stage"]}
        finally:
            os.close(fd)
    finally:
        os.close(lock_fd)


def uninstall_seal_package_handoff():
    """Seal typed owner retirement for generic purge and Debian prerm."""
    need(sys.platform == "linux" and os.geteuid() == 0)
    lock_fd = _open_original_lock("/run/aegis-auto-install.lock", 9,
                                  allow_uninstall=True, create=True)
    try:
        fd = uninstall_journal.directory()
        try:
            intent, phases = uninstall_journal.read(fd)
            need(len(phases) >= 6 and phases[5][0]["state"] == "owners-archived")
            backup_sha = phases[2][0]["backup_manifest_sha256"]
            uninstall_journal.verify_backup(fd, UNINSTALL_OWNERS, backup_sha)
            for owner in UNINSTALL_OWNERS:
                need(not Path(owner).exists() and not Path(owner).is_symlink())
            for owner in UNINSTALL_OWNERS[5:]:
                if not _uninstall_owner_is_unit(owner):
                    continue
                facts = _uninstall_unit_stopped(Path(owner).name)
                need(facts["LoadState"] == "not-found" and facts["FragmentPath"] == "")
            _uninstall_unit_stopped("aegis-client.service")
            need(not _uninstall_guard_split())
            _uninstall_nft_table_absent()
            _uninstall_stop_actors()
            auto_root_sha = uninstall_journal.retire_auto_root(fd)
            need(not Path("/var/lib/aegis-auto").exists() and
                 not Path("/var/lib/aegis-auto").is_symlink())
            proof = hashlib.sha256(uninstall_journal.canonical({
                "stage": intent["stage"], "backup_manifest_sha256": backup_sha,
                "owner_retirement_sha256": phases[5][0]["observation_sha256"],
                "guard_release_sha256": phases[3][0]["observation_sha256"],
                "auto_root_archive_sha256": auto_root_sha})).hexdigest()
            _uninstall_stage_recovery_sources(fd)
            if len(phases) == 6:
                intent, phases = uninstall_journal.advance(
                    fd, "package-ready", proof, backup_manifest_sha256=backup_sha)
            if len(phases) == 7:
                intent, phases = uninstall_journal.advance(
                    fd, "terminal", proof, backup_manifest_sha256=backup_sha)
            uninstall_journal.seal_package_handoff(fd)
            return {"state": "terminal", "stage": intent["stage"]}
        finally:
            os.close(fd)
    finally:
        os.close(lock_fd)


def _uninstall_stage_recovery_sources(journal_fd, *, passive=False):
    """Retain the Python entry point across dpkg's removal of package helpers."""
    try:
        os.mkdir("recovery", 0o700, dir_fd=journal_fd)
        os.fsync(journal_fd)
    except FileExistsError:
        pass
    recovery = os.open("recovery", os.O_RDONLY | os.O_DIRECTORY |
                       os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=journal_fd)
    try:
        info = os.fstat(recovery)
        need(stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == 0 and
             stat.S_IMODE(info.st_mode) == 0o700)
        names = ("aegis_installer_auto_v2.py", "aegis_auto_uninstall_journal.py")
        result = {}
        for name in names:
            source = Path("/usr/local/lib/aegis/helpers/lib") / name
            raw = bounded_root_bytes(source, 4 << 20, (0o500,))
            uninstall_journal.publish(recovery, name, raw, maximum=4 << 20)
            result[name] = hashlib.sha256(raw).hexdigest()
        if passive:
            raw = bounded_root_bytes("/usr/local/lib/aegis/helpers/purge-installed-aegis.sh",
                                     4 << 20, (0o755,))
            uninstall_journal.publish(recovery, "purge-installed-aegis.sh", raw, maximum=4 << 20)
            result["purge-installed-aegis.sh"] = hashlib.sha256(raw).hexdigest()
        resume = (b"If the packaged public uninstall command was removed during dpkg purge, "
                  b"transfer scripts/aegis-ubuntu-uninstall.sh from the exact trusted "
                  b"source commit and run:\n"
                  b"ssh HOST 'sudo bash -s -- purge' < "
                  b"scripts/aegis-ubuntu-uninstall.sh\n"
                  b"The trusted script verifies root ownership, modes and retained "
                  b"source hashes before resuming. Do not execute retained Python directly.\n")
        uninstall_journal.publish(recovery, "resume-command.txt", resume,
                                  maximum=8192)
        result["resume-command.txt"] = hashlib.sha256(resume).hexdigest()
        uninstall_journal.publish(recovery, "recovery-manifest.json",
            uninstall_journal.canonical(result), maximum=8192)
        return result
    finally:
        os.close(recovery)


def _uninstall_generic_purge_proof():
    """Check terminal generic residue while retaining prerm's journal helper."""
    _uninstall_generic_roots_absent()
    for name in ("/usr/local/bin/aegis-client", "/usr/bin/aegis-client",
                 "/var/lib/aegis-install/client", "/var/lib/aegis-client",
                 "/etc/aegis/client", "/var/log/aegis-client"):
        need(not Path(name).exists() and not Path(name).is_symlink())
    _uninstall_unit_stopped("aegis-client.service")
    need(not _uninstall_guard_split())
    _uninstall_nft_table_absent()
    for tool in ("/usr/sbin/iptables-save", "/usr/sbin/ip6tables-save"):
        text = call_output([tool], maximum=128 << 10, timeout=10)
        need(b"AEGIS_WIDE" not in text)
    links = call_output(["/usr/sbin/ip", "-o", "link", "show"],
                        maximum=128 << 10, timeout=10)
    need(b"aegis-tun" not in links)
    return hashlib.sha256(uninstall_journal.canonical({
        "client_binary": "absent", "client_state": "absent",
        "device_guard": "absent", "wide_iptables": "absent",
        "capture_interface": "absent"})).hexdigest()


def _uninstall_generic_roots_absent(root="/"):
    """Every copied client data root must be absent before a purge receipt."""
    for source in uninstall_journal._generic_roots(passive=False):
        path = Path(root) / source.lstrip("/")
        need(not path.exists() and not path.is_symlink())


def _uninstall_package_purge_proof():
    result = _uninstall_dpkg_status()
    need(len(result.stdout) <= 1024 and len(result.stderr) <= 1024 and
         ((result.returncode == 1 and result.stdout == b"" and
           result.stderr == b"dpkg-query: no packages found matching aegis-client\n") or
          (result.returncode == 0 and
           result.stdout == b"unknown ok not-installed")))
    for name in ("/usr/local/lib/aegis/helpers/lib/aegis_auto_uninstall_journal.py",
                 "/usr/local/lib/aegis/helpers/lib/aegis_installer_auto_v2.py"):
        need(not Path(name).exists() and not Path(name).is_symlink())
    for unit in FRESH_CLIENT_UNITS:
        name = Path("/etc/systemd/system") / unit
        need(not name.exists() and not name.is_symlink())
        facts = _uninstall_unit_stopped(unit)
        need(facts["LoadState"] == "not-found" and facts["FragmentPath"] == "")
    return hashlib.sha256(b"aegis-client-package-purged-v1").hexdigest()


def _uninstall_dpkg_retry_needed(status):
    """Admit exact dpkg crash states; never treat an arbitrary query error as absent."""
    need(len(status.stdout) <= 1024 and len(status.stderr) <= 1024)
    retry = {b"install ok installed", b"deinstall ok config-files",
             b"purge ok config-files", b"deinstall ok half-installed",
             b"purge ok half-installed", b"install ok half-installed"}
    if status.returncode == 1:
        need(status.stdout == b"" and status.stderr ==
             b"dpkg-query: no packages found matching aegis-client\n")
        return False
    need(status.returncode == 0 and
         (status.stdout in retry or status.stdout == b"unknown ok not-installed"))
    return status.stdout in retry


def _uninstall_dpkg_status():
    environment = os.environ.copy()
    environment["LC_ALL"] = "C"
    return subprocess.run(["/usr/bin/dpkg-query", "--show",
                           "--showformat=${Status}", "aegis-client"],
                          stdin=subprocess.DEVNULL, capture_output=True,
                          timeout=10, check=False, env=environment)


def uninstall_purge():
    """Complete generic residue removal, then let dpkg consume typed handoff."""
    need(sys.platform == "linux" and os.geteuid() == 0)
    fd = uninstall_journal.directory()
    try:
        intent, phases = uninstall_journal.read(fd)
        need(len(phases) == len(uninstall_journal.STATES) and
             not uninstall_journal.absent(fd, "package-handoff.json"))
        # Includes config, state, logs and the dedicated account home. A
        # replay after partial generic deletion verifies the retained copy
        # and never rebuilds it from already-mutated live roots.
        uninstall_journal.backup_generic_roots(fd)
        if uninstall_journal.absent(fd, "generic-purged.json"):
            helper = Path("/usr/local/lib/aegis/helpers/purge-installed-aegis.sh")
            held = held_root_file(helper, 4 << 20, (0o555, 0o755))
            os.close(held)
            call_output(["/usr/bin/bash", str(helper), "client", "--force"],
                        maximum=32768, timeout=600, diagnostic_stderr=True)
            proof = _uninstall_generic_purge_proof()
            uninstall_journal.record_effect(fd, "generic-purged", proof)
        else:
            proof = _uninstall_generic_purge_proof()
            effect = uninstall_journal.strict_json(uninstall_journal.leaf(
                fd, "generic-purged.json"))
            need(effect["observation_sha256"] == proof)
        if uninstall_journal.absent(fd, "package-purged.json"):
            status = _uninstall_dpkg_status()
            if _uninstall_dpkg_retry_needed(status):
                call_output(["/usr/bin/dpkg", "--purge", "aegis-client"],
                            maximum=32768, timeout=600, diagnostic_stderr=True)
            call_output(["/usr/bin/systemctl", "daemon-reload"], maximum=1024,
                        timeout=15)
            package_proof = _uninstall_package_purge_proof()
            uninstall_journal.record_effect(fd, "package-purged", package_proof)
        else:
            package_proof = _uninstall_package_purge_proof()
            effect = uninstall_journal.strict_json(uninstall_journal.leaf(
                fd, "package-purged.json"))
            need(effect["observation_sha256"] == package_proof)
        final = hashlib.sha256(uninstall_journal.canonical({
            "generic": proof, "package": package_proof,
            "intent": hashlib.sha256(uninstall_journal.canonical(intent)).hexdigest()})).hexdigest()
        uninstall_journal.record_effect(fd, "completed", final)
        uninstall_journal.archive_completed(fd)
        return {"state": "completed", "stage": intent["stage"]}
    finally:
        os.close(fd)


def _passive_removal_payload(value):
    """Closed, build-time SHA roster carried by the package's own maintscripts."""
    need(type(value) is dict and set(value) == {"files", "install_sha256", "package_version"})
    need(type(value["package_version"]) is str and
         re.fullmatch(r"[A-Za-z0-9.+:~_-]{1,128}", value["package_version"]))
    need(type(value["install_sha256"]) is str and
         re.fullmatch(r"[0-9a-f]{64}", value["install_sha256"]))
    expected = {"usr/local/bin/aegis-client": 0o755}
    for name in FRESH_CLIENT_HELPERS:
        expected["usr/local/lib/aegis/helpers/" + name] = (
            0o500 if name.startswith("lib/aegis_auto_") or name in (
                "lib/aegis_installer_auto_v2.py", "lib/aegis_initrd_policy.py",
                "lib/aegis_initrd_classic.py", "lib/aegis-auto-terminal-hook") else 0o755)
    expected.update({"etc/systemd/system/" + name: 0o644 for name in FRESH_CLIENT_UNITS})
    need(type(value["files"]) is dict and set(value["files"]) == set(expected))
    for name, mode in expected.items():
        row = value["files"][name]
        need(type(row) is dict and set(row) == {"sha256", "mode", "retained_mode"} and
             type(row["sha256"]) is str and re.fullmatch(r"[0-9a-f]{64}", row["sha256"]) and
             type(row["mode"]) is int and row["mode"] == mode and
             row["retained_mode"] in (0o444, 0o555))
    return hashlib.sha256(uninstall_journal.canonical(value)).hexdigest()


def _passive_removal_no_owner():
    # Package files do not constitute activation authority. All durable V2
    # namespaces and every independently installed guard remain hard fences.
    for name in (*UNINSTALL_OWNERS[:5], uninstall_journal.BOOT_STORE_ROOT,
                 "/var/lib/aegis-install/client",
                 "/var/lib/aegis-install/auto-client",
                 "/etc/systemd/system/aegis-device-egress-guard.service",
                 "/etc/systemd/system/aegis-client.service",
                 "/etc/aegis-auto-terminal-source.json",
                 "/etc/aegis-auto-terminal-store.json",
                 "/usr/lib/systemd/system-shutdown/aegis-auto-terminal-hook",
                 "/etc/systemd/system/NetworkManager.service.d/31-aegis-auto-terminal-transition.conf",
                 "/etc/systemd/system/systemd-networkd.service.d/31-aegis-auto-terminal-transition.conf",
                 "/etc/systemd/system/networking.service.d/31-aegis-auto-terminal-transition.conf"):
        path = Path(name)
        need(not path.exists() and not path.is_symlink())
    for name in (*FRESH_CLIENT_UNITS, "aegis-client.service",
                 "aegis-device-egress-guard.service"):
        path = Path("/etc/systemd/system") / (name + ".d")
        need(not path.exists() and not path.is_symlink())
    need(not call_output(["/usr/bin/systemctl", "list-units", "--all", "--plain",
                          "--no-legend", "--no-pager", "aegis-auto@*.service"],
                         maximum=65536, timeout=10).strip())
    _uninstall_terminal_instances_stopped()
    _uninstall_no_queued_actor_jobs()
    _uninstall_nft_table_absent()
    for tool in ("/usr/sbin/iptables-save", "/usr/sbin/ip6tables-save"):
        need(b"AEGIS_WIDE" not in call_output([tool], maximum=128 << 10, timeout=10))
    need(b"aegis-tun" not in call_output(["/usr/sbin/ip", "-o", "link", "show"],
                                        maximum=128 << 10, timeout=10))


def _passive_removal_actors(*, removed=False):
    for name in (*FRESH_CLIENT_UNITS, "aegis-client.service", "aegis-device-egress-guard.service"):
        facts = _uninstall_unit_stopped(name)
        if name == "aegis-device-egress-guard.service" or removed:
            need(facts["LoadState"] == "not-found" and facts["FragmentPath"] == "")
        else:
            expected = ("/usr/lib/systemd/system/" if name == "aegis-client.service"
                        else "/etc/systemd/system/") + name
            need(facts["LoadState"] == "loaded" and facts["FragmentPath"] == expected)


def _passive_removal_journal_kind():
    try:
        fd = uninstall_journal.directory()
    except FileNotFoundError:
        return None
    try:
        if uninstall_journal.absent(fd, "intent.json"):
            return "pending"
        intent = uninstall_journal.strict_json(uninstall_journal.leaf(fd, "intent.json"))
        if intent.get("schema") == uninstall_journal.PASSIVE_SCHEMA:
            uninstall_journal.passive_intent(fd)
            return "passive"
        uninstall_journal.read(fd)
        return "active"
    finally:
        os.close(fd)


def _passive_removal_recheck_held(held, payload):
    for fd, name, expected_sha in held:
        os.lseek(fd, 0, os.SEEK_SET)
        need(file_sha(fd)[1] == expected_sha)
        named = held_root_file(name, 256 << 20, (payload["files"][name.lstrip("/")]["mode"],))
        try:
            first, second = os.fstat(fd), os.fstat(named)
            need((first.st_dev, first.st_ino, first.st_size, first.st_mtime_ns, first.st_ctime_ns) ==
                 (second.st_dev, second.st_ino, second.st_size, second.st_mtime_ns, second.st_ctime_ns))
        finally:
            os.close(named)


def _passive_removal_recheck_payload(payload):
    _passive_removal_payload(payload)
    held = []
    try:
        for relative, row in payload["files"].items():
            fd = held_root_file("/" + relative, 256 << 20, (row["mode"],))
            held.append((fd, "/" + relative, row["sha256"]))
        _passive_removal_recheck_held(held, payload)
    finally:
        for fd, _name, _sha in held:
            os.close(fd)


def passive_package_prerm(payload):
    """Admit only an exact unarmed DEB, preserving a barrier across dpkg execs."""
    need(sys.platform == "linux" and os.geteuid() == 0)
    payload_sha = _passive_removal_payload(payload)
    kind = _passive_removal_journal_kind()
    if kind == "active":
        for name in UNINSTALL_OWNERS:
            need(not Path(name).exists() and not Path(name).is_symlink())
        uninstall_journal.verify_package_handoff(payload["package_version"])
        return {"state": "active-package-handoff"}
    lock = _open_original_lock("/run/aegis-auto-install.lock", 9,
                               allow_uninstall=True, create=True)
    held = []
    try:
        _passive_removal_no_owner()
        status = call_output(["/usr/bin/dpkg-query", "--show",
                              "--showformat=${Status}\n${Version}\n", "aegis-client"],
                             maximum=512, timeout=10).decode("ascii").splitlines()
        # dpkg deferred_remove changes installed -> half-configured before
        # executing prerm (src/main/remove.c), then half-installed before
        # deleting files. Exact unarmed payload proof is required in both
        # admissible pre-deletion states; this is not postrm authority.
        need(len(status) == 2 and status[0] in ("install ok installed", "deinstall ok installed",
                                              "purge ok installed", "install ok half-configured",
                                              "deinstall ok half-configured", "purge ok half-configured") and
             status[1] == payload["package_version"])
        for relative, row in payload["files"].items():
            fd = held_root_file("/" + relative, 256 << 20, (row["mode"],))
            held.append((fd, "/" + relative, row["sha256"]))
            need(file_sha(fd)[1] == row["sha256"])
        _passive_removal_actors()
        journal = uninstall_journal.directory(create=True)
        try:
            if uninstall_journal.absent(journal, "intent.json"):
                intent = {"schema": uninstall_journal.PASSIVE_SCHEMA, "package": "aegis-client",
                          "version": payload["package_version"], "payload_sha256": payload_sha,
                          "boot_id": current_boot(), "nonce": secrets.token_hex(16)}
                uninstall_journal.validate_passive_intent(intent)
            else:
                intent = uninstall_journal.passive_intent(journal)
                need(intent["payload_sha256"] == payload_sha and
                     intent["version"] == payload["package_version"])
            # Reopen each name while retaining the original FD. Publication
            # cannot authorize a replaced inode or changed source generation.
            _passive_removal_recheck_held(held, payload)
            _passive_removal_no_owner()
            _passive_removal_actors()
            uninstall_journal.publish(journal, "intent.json", uninstall_journal.canonical(intent))
            uninstall_journal.publish(journal, "passive-payload.json",
                                       uninstall_journal.canonical(payload), maximum=128 << 10)
            _uninstall_stage_recovery_sources(journal, passive=True)
            _passive_removal_stage_helpers(journal, payload)
            uninstall_journal.backup_generic_roots(journal, passive=True)
            _passive_removal_recheck_held(held, payload)
            _passive_removal_no_owner()
            _passive_removal_actors()
            return {"state": "passive-package-removal-admitted", "nonce": intent["nonce"]}
        finally:
            os.close(journal)
    finally:
        for fd, _name, _sha in held:
            os.close(fd)
        os.close(lock)


def _passive_removal_archive(fd, intent):
    parent = directory(Path("/var/lib"))
    try:
        named = os.stat("aegis-auto-uninstall", dir_fd=parent, follow_symlinks=False)
        info = os.fstat(fd)
        need((named.st_dev, named.st_ino) == (info.st_dev, info.st_ino))
        destination = "aegis-auto-passive-uninstall-completed-" + intent["nonce"]
        uninstall_journal.rename_noreplace(parent, "aegis-auto-uninstall", destination)
        os.fsync(parent)
        return {"state": "passive-package-removed", "retained": destination}
    finally:
        os.close(parent)


def _passive_removed_payload(payload):
    for relative in (*payload["files"], "usr/lib/systemd/system/aegis-client.service"):
        path = Path("/" + relative)
        need(not path.exists() and not path.is_symlink())


def passive_package_postrm(payload, action="remove"):
    """Clear the passive barrier only after actual payload and actor removal."""
    need(sys.platform == "linux" and os.geteuid() == 0)
    payload_sha = _passive_removal_payload(payload)
    kind = _passive_removal_journal_kind()
    if kind in (None, "active"):
        return {"state": "no-passive-handoff"}
    need(kind == "passive")
    need(action in ("remove", "purge"))
    lock = _open_original_lock("/run/aegis-auto-install.lock", 9,
                               allow_uninstall=True, create=True)
    try:
        fd = uninstall_journal.directory()
        try:
            intent = uninstall_journal.passive_intent(fd)
            need(intent["payload_sha256"] == payload_sha and
                 uninstall_journal.leaf(fd, "passive-payload.json", maximum=128 << 10) ==
                 uninstall_journal.canonical(payload))
            uninstall_journal.verify_generic_backup(fd, passive=True)
            status = call_output(["/usr/bin/dpkg-query", "--show",
                                  "--showformat=${Status}\n${Version}\n", "aegis-client"],
                                 maximum=512, timeout=10).decode("ascii").splitlines()
            need(len(status) == 2 and status[1] == payload["package_version"] and
                 status[0] in ("deinstall ok half-installed", "purge ok half-installed",
                               "deinstall ok config-files", "purge ok config-files"))
            _passive_removal_no_owner()
            _passive_removed_payload(payload)
            call_output(["/usr/bin/systemctl", "daemon-reload"], maximum=1024, timeout=15)
            _passive_removal_actors(removed=True)
            _passive_removal_no_owner()
            uninstall_journal.publish(fd, "removed.json", uninstall_journal.canonical({
                "schema": "aegis_auto_v2_passive_package_removed_v1",
                "intent_sha256": hashlib.sha256(uninstall_journal.canonical(intent)).hexdigest(),
                "payload_sha256": payload_sha}))
            # dpkg -r retains the barrier and recovery source until -P or the
            # public purge wrapper. A full wrapper keeps it through generic
            # cleanup as well, so neither preinst nor AUTO can race that sweep.
            return {"state": "passive-package-removed-awaiting-generic-purge"}
        finally:
            os.close(fd)
    finally:
        os.close(lock)


def passive_package_uninstall():
    """Use the DEB handoff, then purge residual data under a fresh InstallLock."""
    import ast
    kind = _passive_removal_journal_kind()
    if kind == "passive":
        fd = uninstall_journal.directory()
        try:
            payload = uninstall_journal.strict_json(uninstall_journal.leaf(
                fd, "passive-payload.json", maximum=128 << 10))
        finally:
            os.close(fd)
    else:
        need(kind in (None, "pending"))
        if kind is None and not Path("/var/lib/dpkg/info/aegis-client.prerm").exists():
            _uninstall_package_purge_proof()
            _uninstall_generic_purge_proof()
            return {"state": "completed", "method": "passive-package-observed-absent"}
        raw = bounded_root_bytes("/var/lib/dpkg/info/aegis-client.prerm", 4 << 20, (0o755,))
        tree = ast.parse(raw)
        rows = [node for node in tree.body if isinstance(node, ast.Assign) and
                len(node.targets) == 1 and isinstance(node.targets[0], ast.Name) and
                node.targets[0].id == "EXPECTED"]
        need(len(rows) == 1 and isinstance(rows[0].value, ast.Call) and
             len(rows[0].value.args) == 1 and isinstance(rows[0].value.args[0], ast.Constant) and
             type(rows[0].value.args[0].value) is str)
        payload = strict_json(rows[0].value.args[0].value)
        passive_package_prerm(payload)
    _passive_removal_payload(payload)
    lock = _open_original_lock("/run/aegis-auto-install.lock", 9,
                               allow_uninstall=True, create=True)
    try:
        fd = uninstall_journal.directory()
        try:
            intent = uninstall_journal.passive_intent(fd)
            need(intent["payload_sha256"] == hashlib.sha256(uninstall_journal.canonical(payload)).hexdigest())
            script = bounded_root_bytes("/var/lib/aegis-auto-uninstall/recovery/purge-installed-aegis.sh",
                                        4 << 20, (0o600,))
            need(hashlib.sha256(script).hexdigest() == payload["files"][
                "usr/local/lib/aegis/helpers/purge-installed-aegis.sh"]["sha256"])
            uninstall_journal.publish(fd, "purge-residue-intent.json", uninstall_journal.canonical({
                "schema": "aegis_auto_v2_passive_generic_purge_intent_v1",
                "intent_sha256": hashlib.sha256(uninstall_journal.canonical(intent)).hexdigest()}))
        finally:
            os.close(fd)
    finally:
        os.close(lock)
    call_output(["/usr/bin/dpkg", "--purge", "aegis-client"], maximum=32768,
                timeout=600, diagnostic_stderr=True)
    # A retry after deletion may have reached postrm without the old prerm.
    lock = _open_original_lock("/run/aegis-auto-install.lock", 9,
                               allow_uninstall=True, create=True)
    try:
        verify_passive_generic_handoff(9)
        helper_root = _passive_removal_verify_helpers(payload)
        call_output(["/usr/bin/bash", str(helper_root / "purge-installed-aegis.sh"),
                     "client", "--force"], maximum=32768, timeout=600,
                    pass_fds=(9,), diagnostic_stderr=True)
        _uninstall_generic_purge_proof()
        _uninstall_package_purge_proof()
        fd = uninstall_journal.directory()
        try:
            _passive_removal_archive(fd, intent)
        finally:
            os.close(fd)
        return {"state": "completed", "method": "passive-package", "nonce": intent["nonce"]}
    finally:
        os.close(lock)


def verify_passive_generic_handoff(install_fd):
    """Read-only admission for the retained generic script under our same OFD."""
    need(sys.platform == "linux" and os.geteuid() == 0)
    fresh_package_lock(install_fd, allow_uninstall=True)
    need(_passive_removal_journal_kind() == "passive")
    fd = uninstall_journal.directory()
    try:
        intent = uninstall_journal.passive_intent(fd)
        payload = uninstall_journal.strict_json(uninstall_journal.leaf(
            fd, "passive-payload.json", maximum=128 << 10))
        need(_passive_removal_payload(payload) == intent["payload_sha256"])
        expected_intent = hashlib.sha256(uninstall_journal.canonical(intent)).hexdigest()
        need(uninstall_journal.strict_json(uninstall_journal.leaf(fd, "purge-residue-intent.json")) == {
            "schema": "aegis_auto_v2_passive_generic_purge_intent_v1", "intent_sha256": expected_intent})
        need(uninstall_journal.strict_json(uninstall_journal.leaf(fd, "removed.json")) == {
            "schema": "aegis_auto_v2_passive_package_removed_v1", "intent_sha256": expected_intent,
            "payload_sha256": intent["payload_sha256"]})
        uninstall_journal.verify_generic_backup(fd, passive=True)
        _passive_removed_payload(payload)
        _uninstall_package_purge_proof()
        _passive_removal_no_owner()
        _passive_removal_actors(removed=True)
        return True
    finally:
        os.close(fd)


def _passive_removal_verify_helpers(payload):
    """Verify the entire retained dependency tree before running any helper."""
    root = Path("/var/lib/aegis-auto-uninstall/recovery/helpers")
    names = FRESH_CLIENT_HELPERS
    for directory_name, wanted in ((root, {"lib", *(name for name in names if "/" not in name)}),
                                   (root / "lib", {name[4:] for name in names if name.startswith("lib/")})):
        fd = directory(directory_name, 0o700)
        try:
            need(set(os.listdir(fd)) == wanted)
        finally:
            os.close(fd)
    for name in names:
        row = payload["files"]["usr/local/lib/aegis/helpers/" + name]
        need(hashlib.sha256(bounded_root_bytes(root / name, 4 << 20,
                                               (row["mode"],))).hexdigest() == row["sha256"])
    return root


def _passive_removal_stage_helpers(journal_fd, payload):
    """Preserve a real absolute script path and its complete package closure."""
    recovery = os.open("recovery", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW |
                       os.O_CLOEXEC, dir_fd=journal_fd)
    try:
        if not uninstall_journal.absent(recovery, "helpers"):
            return _passive_removal_verify_helpers(payload)
        if not uninstall_journal.absent(recovery, "pending-helpers"):
            uninstall_journal.rename_noreplace(recovery, "pending-helpers",
                                               "failed-helpers-" + secrets.token_hex(16))
            os.fsync(recovery)
        os.mkdir("pending-helpers", 0o700, dir_fd=recovery)
        pending = os.open("pending-helpers", os.O_RDONLY | os.O_DIRECTORY |
                          os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=recovery)
        try:
            os.mkdir("lib", 0o700, dir_fd=pending)
            library = os.open("lib", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW |
                              os.O_CLOEXEC, dir_fd=pending)
            try:
                for name in FRESH_CLIENT_HELPERS:
                    row = payload["files"]["usr/local/lib/aegis/helpers/" + name]
                    raw = bounded_root_bytes(Path("/usr/local/lib/aegis/helpers") / name,
                                             4 << 20, (row["mode"],))
                    need(hashlib.sha256(raw).hexdigest() == row["sha256"])
                    parent, leaf = (library, name[4:]) if name.startswith("lib/") else (pending, name)
                    fd = os.open(leaf, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                                 os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=parent)
                    try:
                        view = memoryview(raw)
                        while view:
                            view = view[os.write(fd, view):]
                        os.fchmod(fd, row["mode"])
                        os.fsync(fd)
                    finally:
                        os.close(fd)
                os.fsync(library)
                os.fsync(pending)
            finally:
                os.close(library)
        finally:
            os.close(pending)
        uninstall_journal.rename_noreplace(recovery, "pending-helpers", "helpers")
        os.fsync(recovery)
        return _passive_removal_verify_helpers(payload)
    finally:
        os.close(recovery)


def uninstall_all():
    """Resume each durable typed phase and finish package removal in one call."""
    need(sys.platform == "linux" and os.geteuid() == 0)
    kind = _passive_removal_journal_kind()
    if kind == "passive" or (kind in (None, "pending") and
            not any(Path(name).exists() or Path(name).is_symlink() for name in UNINSTALL_OWNERS[:5])):
        return passive_package_uninstall()
    try:
        fd = uninstall_journal.directory()
    except FileNotFoundError:
        begin_uninstall()
    else:
        try:
            if uninstall_journal.absent(fd, "intent.json"):
                begin_uninstall()
            else:
                intent, phases = uninstall_journal.read(fd)
                if not phases and intent["boot_id"] == current_boot():
                    begin_uninstall()
        finally:
            os.close(fd)
    operations = (
        (2, uninstall_stop_and_archive),
        (3, uninstall_prepare_guard),
        (4, uninstall_recover_guard),
        (5, uninstall_seal_actors),
        (6, uninstall_archive_owners),
        (8, uninstall_seal_package_handoff),
    )
    for required, action in operations:
        fd = uninstall_journal.directory()
        try:
            _intent, phases = uninstall_journal.read(fd)
        finally:
            os.close(fd)
        if len(phases) < required:
            action()
    return uninstall_purge()


if __name__ == "__main__":
    raise SystemExit(main())
