"""Durable AUTO V2 uninstall intent and terminal package handoff.

This module stores authority only. Callers must independently authenticate live
Stop, guard, actor and owner facts before advancing a phase. It never disarms a
policy or removes an owner. The journal lives outside the retired control tree.
"""

import hashlib
import json
import os
import re
import stat
import sys
import ctypes
import secrets
import shutil
from pathlib import Path

SCHEMA = "aegis_auto_v2_uninstall_intent_v1"
PASSIVE_SCHEMA = "aegis_auto_v2_passive_package_removal_v1"
PHASE_SCHEMA = "aegis_auto_v2_uninstall_phase_v1"
TERMINAL_SCHEMA = "aegis_auto_v2_uninstall_package_handoff_v1"
JOURNAL = ("var", "lib", "aegis-auto-uninstall")
STATES = (
    "admitted", "stopped-archived", "guard-recovering", "guard-released",
    "actors-quiescent", "owners-archived", "package-ready", "terminal",
)
EFFECTS = ("generic-purged", "package-purged", "completed")
HEX = re.compile(r"[0-9a-f]{64}\Z")
UUID = re.compile(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\Z")
STAGE = re.compile(r"/run/aegis-installer-config-snapshots/[A-Za-z0-9._-]+\Z")


class Refused(ValueError):
    pass


def need(condition):
    if not condition:
        raise Refused("AUTO uninstall journal refused")


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def sha(value):
    return hashlib.sha256(value).hexdigest()


def strict_json(raw):
    def pairs(items):
        result = dict(items)
        need(len(result) == len(items))
        return result
    value = json.loads(raw, object_pairs_hook=pairs)
    need(canonical(value) == raw)
    return value


def checked_dir(fd, owner, group):
    info = os.fstat(fd)
    need(stat.S_ISDIR(info.st_mode) and info.st_uid == owner and
         info.st_gid == group and not stat.S_IMODE(info.st_mode) & 0o022)


def directory(root="/", *, create=False, owner=0, group=0):
    """Open fixed root-owned journal components without following a link."""
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        for index, part in enumerate(JOURNAL):
            checked_dir(fd, owner, group)
            if create and index == len(JOURNAL) - 1:
                try:
                    os.mkdir(part, 0o700, dir_fd=fd)
                    os.fsync(fd)
                except FileExistsError:
                    pass
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY |
                            os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
            checked_dir(child, owner, group)
            if index == len(JOURNAL) - 1:
                need(stat.S_IMODE(os.fstat(child).st_mode) == 0o700)
            os.close(fd)
            fd = child
        return fd
    except BaseException:
        os.close(fd)
        raise


def leaf(fd, name, *, owner=0, group=0, maximum=8192):
    need(re.fullmatch(r"[a-z0-9._-]+", name) is not None)
    child = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK |
                    os.O_CLOEXEC, dir_fd=fd)
    try:
        before = os.fstat(child)
        need(stat.S_ISREG(before.st_mode) and before.st_uid == owner and
             before.st_gid == group and before.st_nlink == 1 and
             stat.S_IMODE(before.st_mode) == 0o600 and 0 < before.st_size <= maximum)
        raw = os.read(child, maximum + 1)
        after = os.fstat(child)
        named = os.stat(name, dir_fd=fd, follow_symlinks=False)
        need(len(raw) == before.st_size and
             (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns,
              before.st_ctime_ns) ==
             (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns,
              after.st_ctime_ns) and
             (named.st_dev, named.st_ino) == (before.st_dev, before.st_ino))
        return raw
    finally:
        os.close(child)


def absent(fd, name):
    try:
        os.stat(name, dir_fd=fd, follow_symlinks=False)
    except FileNotFoundError:
        return True
    return False


def publish(fd, name, raw, *, owner=0, group=0, maximum=8192):
    """Fsync a sibling, then no-replace rename; replay a partial sibling safely."""
    need(len(raw) <= maximum and raw)
    pending = f"pending-{name}"
    if not absent(fd, name):
        need(leaf(fd, name, owner=owner, group=group, maximum=maximum) == raw)
        need(absent(fd, pending))
        return
    if not absent(fd, pending):
        info = os.stat(pending, dir_fd=fd, follow_symlinks=False)
        need(stat.S_ISREG(info.st_mode) and info.st_uid == owner and
             info.st_gid == group and info.st_nlink == 1 and
             stat.S_IMODE(info.st_mode) == 0o600)
        try:
            old = leaf(fd, pending, owner=owner, group=group, maximum=maximum)
        except Refused:
            old = None
        if old != raw:
            failed = f"failed-{secrets.token_hex(16)}.json"
            rename_noreplace(fd, pending, failed)
            os.fsync(fd)
    if absent(fd, pending):
        child = os.open(pending, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                        os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=fd)
        try:
            view = memoryview(raw)
            while view:
                view = view[os.write(child, view):]
            os.fsync(child)
        finally:
            os.close(child)
        os.fsync(fd)
    need(leaf(fd, pending, owner=owner, group=group, maximum=maximum) == raw)
    rename_noreplace(fd, pending, name)
    os.fsync(fd)
    need(leaf(fd, name, owner=owner, group=group, maximum=maximum) == raw)


def rename_noreplace(fd, old, new, *, target_fd=None):
    need(re.fullmatch(r"[a-z0-9._-]+", old) is not None and
         re.fullmatch(r"[a-z0-9._-]+", new) is not None)
    target_fd = fd if target_fd is None else target_fd
    if sys.platform == "linux":
        libc = ctypes.CDLL(None, use_errno=True)
        operation = libc.renameat2
        operation.argtypes = (ctypes.c_int, ctypes.c_char_p,
                              ctypes.c_int, ctypes.c_char_p, ctypes.c_uint)
        operation.restype = ctypes.c_int
        if operation(fd, old.encode(), target_fd, new.encode(), 1) != 0:
            raise OSError(ctypes.get_errno(), "renameat2 refused")
    else:  # local protocol tests; the installed coordinator is Linux only
        need(absent(target_fd, new))
        os.rename(old, new, src_dir_fd=fd, dst_dir_fd=target_fd)


def validate_intent(value):
    need(type(value) is dict and set(value) == {
        "schema", "boot_id", "stage", "pointer_sha256", "candidate_sha256",
        "owner_manifest_sha256", "guard_config_sha256", "package", "version",
        "backup_root", "nonce",
    })
    need(value["schema"] == SCHEMA and type(value["boot_id"]) is str and
         UUID.fullmatch(value["boot_id"]) is not None and
         type(value["stage"]) is str and STAGE.fullmatch(value["stage"]) is not None)
    for key in ("pointer_sha256", "candidate_sha256", "owner_manifest_sha256",
                "guard_config_sha256"):
        need(type(value[key]) is str and HEX.fullmatch(value[key]) is not None)
    need(value["package"] == "aegis-client" and type(value["version"]) is str and
         re.fullmatch(r"[A-Za-z0-9.+:~_-]{1,128}", value["version"]) is not None)
    need(value["backup_root"] == "/var/lib/aegis-auto-uninstall/backup" and
         type(value["nonce"]) is str and
         re.fullmatch(r"[0-9a-f]{32}", value["nonce"]) is not None)


def validate_passive_intent(value):
    """A passive removal is a barrier, never authority to stop an AUTO owner."""
    need(type(value) is dict and set(value) == {
        "schema", "package", "version", "payload_sha256", "boot_id", "nonce"})
    need(value["schema"] == PASSIVE_SCHEMA and value["package"] == "aegis-client")
    need(type(value["version"]) is str and
         re.fullmatch(r"[A-Za-z0-9.+:~_-]{1,128}", value["version"]) is not None)
    need(type(value["payload_sha256"]) is str and HEX.fullmatch(value["payload_sha256"]) is not None)
    need(type(value["boot_id"]) is str and UUID.fullmatch(value["boot_id"]) is not None)
    need(type(value["nonce"]) is str and re.fullmatch(r"[0-9a-f]{32}", value["nonce"]) is not None)


def passive_intent(fd, *, owner=0, group=0):
    value = strict_json(leaf(fd, "intent.json", owner=owner, group=group))
    validate_passive_intent(value)
    # An interrupted publication/recovery copy remains a barrier. No active
    # phase or active package handoff may masquerade as this finite protocol.
    need(all(name in ("intent.json", "passive-payload.json", "recovery", "backup", "removed.json",
                     "purge-residue-intent.json") or
             re.fullmatch(r"(?:pending-[a-z0-9._-]+|failed-[0-9a-f]{32}\.json)", name)
             for name in os.listdir(fd)))
    return value


def _phase_name(index):
    need(type(index) is int and 0 <= index < 1000)
    return f"phase-{index:03d}.json"


def _validate_phase(phase, index, intent_sha, previous_sha):
    need(type(phase) is dict and set(phase) == {
        "schema", "index", "state", "intent_sha256", "previous_sha256",
        "observation_sha256", "backup_manifest_sha256", "guard_split_sha256",
    })
    valid_state = ("stopped-archived", "reboot-observed") if index == 1 else (STATES[index],)
    need(phase["schema"] == PHASE_SCHEMA and type(phase["index"]) is int and
         phase["index"] == index and phase["state"] in valid_state and
         phase["intent_sha256"] == intent_sha and
         phase["previous_sha256"] == previous_sha)
    for key in ("observation_sha256", "backup_manifest_sha256", "guard_split_sha256"):
        value = phase[key]
        need(value is None or (type(value) is str and HEX.fullmatch(value) is not None))
    need(phase["observation_sha256"] is not None)
    if index >= 5:
        need(phase["backup_manifest_sha256"] is not None)
    if index in (2, 3):
        need(phase["guard_split_sha256"] is not None)


def read(fd, *, owner=0, group=0):
    """Replay a contiguous, canonical hash chain and reject extra phase files."""
    intent_raw = leaf(fd, "intent.json", owner=owner, group=group)
    intent = strict_json(intent_raw)
    validate_intent(intent)
    intent_sha = sha(intent_raw)
    entries = os.listdir(fd)
    need("intent.json" in entries)
    named = {name for name in entries if name.startswith("phase-")}
    need(all(re.fullmatch(r"phase-[0-9]{3}\.json", name) for name in named))
    phase = None
    previous_sha = intent_sha
    phases = []
    for index in range(len(STATES)):
        name = _phase_name(index)
        if name not in named:
            break
        raw = leaf(fd, name, owner=owner, group=group)
        phase = strict_json(raw)
        _validate_phase(phase, index, intent_sha, previous_sha)
        phases.append((phase, sha(raw)))
        previous_sha = sha(raw)
    need(named == {_phase_name(index) for index in range(len(phases))})
    allowed = {"intent.json", *named}
    if "package-handoff.json" in entries:
        allowed.add("package-handoff.json")
    if "backup" in entries:
        backup = os.open("backup", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW |
                         os.O_CLOEXEC, dir_fd=fd)
        try:
            checked_dir(backup, owner, group)
            need(stat.S_IMODE(os.fstat(backup).st_mode) == 0o700)
        finally:
            os.close(backup)
        allowed.add("backup")
    if "recovery" in entries:
        recovery = os.open("recovery", os.O_RDONLY | os.O_DIRECTORY |
                           os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
        try:
            checked_dir(recovery, owner, group)
            need(stat.S_IMODE(os.fstat(recovery).st_mode) == 0o700)
        finally:
            os.close(recovery)
        allowed.add("recovery")
    byproducts = {name for name in entries if re.fullmatch(
        r"(?:pending-(?:intent|phase-[0-9]{3}|package-handoff|generic-purged|package-purged|completed)|failed-[0-9a-f]{32})\.json",
        name)}
    for name in byproducts:
        info = os.stat(name, dir_fd=fd, follow_symlinks=False)
        need(stat.S_ISREG(info.st_mode) and info.st_uid == owner and
             info.st_gid == group and info.st_nlink == 1 and
             stat.S_IMODE(info.st_mode) == 0o600 and 0 <= info.st_size <= 8192)
    allowed.update(byproducts)
    if "package-handoff.json" in entries:
        need(len(phases) == len(STATES))
        handoff = strict_json(leaf(fd, "package-handoff.json", owner=owner, group=group))
        _validate_handoff(handoff, intent, intent_sha, previous_sha, phases)
    effect_previous = sha(leaf(fd, "package-handoff.json", owner=owner,
                               group=group)) if "package-handoff.json" in entries else None
    for index, effect in enumerate(EFFECTS):
        name = effect + ".json"
        if name not in entries:
            need(not any(later + ".json" in entries for later in EFFECTS[index + 1:]))
            break
        need(effect_previous is not None)
        value = strict_json(leaf(fd, name, owner=owner, group=group))
        need(type(value) is dict and set(value) == {
            "schema", "effect", "intent_sha256", "previous_sha256",
            "observation_sha256"} and
             value["schema"] == "aegis_auto_v2_uninstall_effect_v1" and
             value["effect"] == effect and value["intent_sha256"] == intent_sha and
             value["previous_sha256"] == effect_previous and
             type(value["observation_sha256"]) is str and
             HEX.fullmatch(value["observation_sha256"]) is not None)
        allowed.add(name)
        effect_previous = sha(canonical(value))
    if "retained-location.json" in entries:
        need("completed.json" in entries)
        location = strict_json(leaf(fd, "retained-location.json", owner=owner,
                                    group=group))
        need(location == {
            "schema": "aegis_auto_v2_uninstall_retained_location_v1",
            "intent_sha256": intent_sha,
            "directory": "aegis-auto-uninstall-completed-" + intent["nonce"]})
        allowed.add("retained-location.json")
    need(set(entries) == allowed)
    return intent, phases


def begin(fd, value, *, owner=0, group=0):
    """Publish intent once while caller holds the original InstallLock."""
    validate_intent(value)
    raw = canonical(value)
    if absent(fd, "intent.json"):
        need(all(re.fullmatch(r"(?:pending-intent|failed-[0-9a-f]{32})\.json", name)
                 for name in os.listdir(fd)))
        publish(fd, "intent.json", raw, owner=owner, group=group)
    else:
        need(leaf(fd, "intent.json", owner=owner, group=group) == raw)
    return read(fd, owner=owner, group=group)


def advance(fd, state, observation_sha256, *, backup_manifest_sha256=None,
            guard_split_sha256=None, owner=0, group=0):
    """Append exactly one fsynced phase; a replay of that phase is idempotent."""
    intent, phases = read(fd, owner=owner, group=group)
    need(state in (*STATES, "reboot-observed") and type(observation_sha256) is str and
         HEX.fullmatch(observation_sha256) is not None)
    index = 1 if state == "reboot-observed" else STATES.index(state)
    intent_sha = sha(canonical(intent))
    previous_sha = phases[index - 1][1] if index and index <= len(phases) else intent_sha
    value = {"schema": PHASE_SCHEMA, "index": index, "state": state,
             "intent_sha256": intent_sha, "previous_sha256": previous_sha,
             "observation_sha256": observation_sha256,
             "backup_manifest_sha256": backup_manifest_sha256,
             "guard_split_sha256": guard_split_sha256}
    if index < len(phases):
        need(phases[index][0] == value)
        return intent, phases
    need(index == len(phases) and index < len(STATES))
    _validate_phase(value, index, intent_sha, previous_sha)
    publish(fd, _phase_name(index), canonical(value), owner=owner, group=group)
    return read(fd, owner=owner, group=group)


def _validate_handoff(value, intent, intent_sha, terminal_sha, phases):
    need(type(value) is dict and set(value) == {
        "schema", "intent_sha256", "terminal_phase_sha256", "package",
        "version", "backup_manifest_sha256", "guard_release_sha256",
    })
    need(value["schema"] == TERMINAL_SCHEMA and value["intent_sha256"] == intent_sha and
         value["terminal_phase_sha256"] == terminal_sha and
         value["package"] == intent["package"] and value["version"] == intent["version"] and
         value["backup_manifest_sha256"] == phases[5][0]["backup_manifest_sha256"] and
         value["guard_release_sha256"] == phases[3][0]["observation_sha256"])


def seal_package_handoff(fd, *, owner=0, group=0):
    """Seal terminal identity for prerm after the caller proves owner absence."""
    intent, phases = read(fd, owner=owner, group=group)
    need(len(phases) == len(STATES))
    value = {"schema": TERMINAL_SCHEMA, "intent_sha256": sha(canonical(intent)),
             "terminal_phase_sha256": phases[-1][1], "package": intent["package"],
             "version": intent["version"],
             "backup_manifest_sha256": phases[5][0]["backup_manifest_sha256"],
             "guard_release_sha256": phases[3][0]["observation_sha256"]}
    raw = canonical(value)
    if absent(fd, "package-handoff.json"):
        publish(fd, "package-handoff.json", raw, owner=owner, group=group)
    else:
        need(leaf(fd, "package-handoff.json", owner=owner, group=group) == raw)
    read(fd, owner=owner, group=group)
    return value


def record_effect(fd, effect, observation_sha256, *, owner=0, group=0):
    need(effect in EFFECTS and type(observation_sha256) is str and
         HEX.fullmatch(observation_sha256) is not None)
    intent, phases = read(fd, owner=owner, group=group)
    need(len(phases) == len(STATES))
    index = EFFECTS.index(effect)
    previous = "package-handoff.json" if index == 0 else EFFECTS[index - 1] + ".json"
    previous_raw = leaf(fd, previous, owner=owner, group=group)
    value = {"schema": "aegis_auto_v2_uninstall_effect_v1",
             "effect": effect, "intent_sha256": sha(canonical(intent)),
             "previous_sha256": sha(previous_raw),
             "observation_sha256": observation_sha256}
    raw = canonical(value)
    name = effect + ".json"
    if absent(fd, name):
        publish(fd, name, raw, owner=owner, group=group)
    else:
        need(leaf(fd, name, owner=owner, group=group) == raw)
    read(fd, owner=owner, group=group)
    return value


def verify_package_handoff(version):
    """Read-only prerm gate after typed owner retirement and before dpkg remove."""
    need(sys.platform == "linux" and os.geteuid() == 0 and type(version) is str)
    fd = directory()
    try:
        need(not absent(fd, "package-handoff.json"))
        intent, phases = read(fd)
        need(len(phases) == len(STATES) and intent["version"] == version and
             not absent(fd, "generic-purged.json"))
        verify_recovery_sources(fd)
        verify_generic_backup(fd)
        return True
    finally:
        os.close(fd)


def verify_generic_handoff(version):
    """Pre-deletion gate; prerm's later gate still requires generic-purged."""
    need(sys.platform == "linux" and os.geteuid() == 0 and type(version) is str)
    fd = directory()
    try:
        need(not absent(fd, "package-handoff.json") and
             absent(fd, "generic-purged.json"))
        intent, phases = read(fd)
        need(len(phases) == len(STATES) and intent["version"] == version)
        verify_recovery_sources(fd)
        verify_generic_backup(fd)
        return True
    finally:
        os.close(fd)


def verify_recovery_sources(fd, *, owner=0, group=0):
    recovery = os.open("recovery", os.O_RDONLY | os.O_DIRECTORY |
                       os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
    try:
        checked_dir(recovery, owner, group)
        need(stat.S_IMODE(os.fstat(recovery).st_mode) == 0o700)
        names = ("aegis_installer_auto_v2.py", "aegis_auto_uninstall_journal.py",
                 "resume-command.txt")
        need(set(os.listdir(recovery)) == {*names, "recovery-manifest.json"})
        manifest = strict_json(leaf(recovery, "recovery-manifest.json",
                                    owner=owner, group=group))
        need(type(manifest) is dict and set(manifest) == set(names))
        for name in names:
            need(type(manifest[name]) is str and HEX.fullmatch(manifest[name]) and
                 sha(leaf(recovery, name, owner=owner, group=group,
                          maximum=4 << 20)) == manifest[name])
        need(b"ssh HOST 'sudo bash -s -- purge' < "
             b"scripts/aegis-ubuntu-uninstall.sh\n" in
             leaf(recovery, "resume-command.txt", owner=owner, group=group))
        return manifest
    finally:
        os.close(recovery)


# Selected client data removed by the generic purge, including the dedicated
# account home. This private rollback copy is separate from the eleven V2
# control owners and is never placed in retained QA evidence or Git.
GENERIC_PURGE_ROOTS = (
    "/etc/aegis/client", "/var/lib/aegis-client",
    "/var/log/aegis-client", "/var/lib/aegis-install/client",
    "/var/lib/aegis-install/auto-client", "/var/lib/aegis-client-logs",
    "/etc/systemd/system/aegis-client.service.d",
    "/etc/default/aegis-client",
)
BOOT_STORE_ROOT = "/boot/aegis-auto-terminal"


def _generic_roots(*, passive=False):
    return GENERIC_PURGE_ROOTS if passive else (*GENERIC_PURGE_ROOTS, BOOT_STORE_ROOT)


def _generic_tree_manifest(path, budget):
    """Nofollow, bounded regular-file tree; retain original uid/gid/mode."""
    entries = []
    try:
        top = os.lstat(path)
    except FileNotFoundError:
        return [{"path": ".", "kind": "absent"}]

    def record(relative, info, content=None):
        budget[0] += 1
        need(budget[0] <= 16384 and len(relative) <= 4096 and
             not stat.S_ISLNK(info.st_mode) and
             not (stat.S_IMODE(info.st_mode) & 0o022))
        common = {"path": relative, "uid": info.st_uid, "gid": info.st_gid,
                  "mode": stat.S_IMODE(info.st_mode)}
        if stat.S_ISDIR(info.st_mode):
            entries.append({**common, "kind": "directory"})
        elif stat.S_ISREG(info.st_mode):
            need(info.st_nlink == 1 and info.st_size <= 512 << 20)
            budget[1] += info.st_size
            need(budget[1] <= 512 << 20 and content is not None)
            entries.append({**common, "kind": "file", "size": info.st_size,
                            "sha256": content})
        else:
            raise Refused()

    if stat.S_ISREG(top.st_mode):
        held = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK |
                       os.O_CLOEXEC)
        try:
            actual = os.fstat(held)
            need((actual.st_dev, actual.st_ino, actual.st_size) ==
                 (top.st_dev, top.st_ino, top.st_size))
            digest = hashlib.sha256()
            while chunk := os.read(held, 65536):
                digest.update(chunk)
            need((os.fstat(held).st_size, os.fstat(held).st_mtime_ns) ==
                 (top.st_size, top.st_mtime_ns))
            record(".", top, digest.hexdigest())
        finally:
            os.close(held)
    elif stat.S_ISDIR(top.st_mode):
        for directory, directories, files, parent_fd in os.fwalk(
                path, topdown=True, follow_symlinks=False):
            relative_dir = os.path.relpath(directory, path)
            before = os.fstat(parent_fd)
            record(relative_dir, before)
            for name in sorted(directories + files):
                need(name not in ("", ".", "..") and "/" not in name and
                     len(name) <= 255)
                info = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
                need(not stat.S_ISLNK(info.st_mode))
                if name in directories:
                    need(stat.S_ISDIR(info.st_mode))
                    continue
                need(stat.S_ISREG(info.st_mode))
                held = os.open(name, os.O_RDONLY | os.O_NOFOLLOW |
                               os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=parent_fd)
                try:
                    actual = os.fstat(held)
                    need((actual.st_dev, actual.st_ino, actual.st_size) ==
                         (info.st_dev, info.st_ino, info.st_size))
                    digest = hashlib.sha256()
                    while chunk := os.read(held, 65536):
                        digest.update(chunk)
                    need((os.fstat(held).st_size, os.fstat(held).st_mtime_ns) ==
                         (info.st_size, info.st_mtime_ns))
                    relative = name if relative_dir == "." else relative_dir + "/" + name
                    record(relative, info, digest.hexdigest())
                finally:
                    os.close(held)
            need((os.fstat(parent_fd).st_dev, os.fstat(parent_fd).st_ino,
                  os.fstat(parent_fd).st_mtime_ns) ==
                 (before.st_dev, before.st_ino, before.st_mtime_ns))
        need((os.lstat(path).st_dev, os.lstat(path).st_ino) ==
             (top.st_dev, top.st_ino))
    else:
        raise Refused()
    return sorted(entries, key=lambda entry: entry["path"])


def _generic_contents(entries):
    return [{key: entry[key] for key in ("path", "kind", "size", "sha256")
             if key in entry} for entry in entries]


def verify_generic_backup(fd, *, root="/", owner=0, group=0, passive=False):
    intent = (passive_intent(fd, owner=owner, group=group) if passive else
              read(fd, owner=owner, group=group)[0])
    backup = _ensure_backup(fd, owner=owner, group=group, create=False)
    try:
        manifest = strict_json(leaf(backup, "generic-manifest.json",
                                    owner=owner, group=group, maximum=4 << 20))
        need(type(manifest) is dict and set(manifest) == {
            "schema", "intent_sha256", "roots"} and
             manifest["schema"] == "aegis_auto_v2_generic_purge_backup_v1" and
             manifest["intent_sha256"] == sha(canonical(intent)) and
             type(manifest["roots"]) is list and
             len(manifest["roots"]) == len(_generic_roots(passive=passive)))
        generic = os.open("generic", os.O_RDONLY | os.O_DIRECTORY |
                          os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=backup)
        try:
            checked_dir(generic, owner, group)
            need(stat.S_IMODE(os.fstat(generic).st_mode) == 0o700 and
                 leaf(generic, "manifest.json", owner=owner, group=group,
                      maximum=4 << 20) == canonical(manifest))
            need(set(os.listdir(generic)) == {"manifest.json"} |
                 {"generic-%02d" % index for index, item in
                  enumerate(manifest["roots"]) if item["entries"] !=
                  [{"path": ".", "kind": "absent"}]})
            for index, source in enumerate(_generic_roots(passive=passive)):
                item = manifest["roots"][index]
                need(type(item) is dict and set(item) == {"source", "entries"} and
                     item["source"] == source and type(item["entries"]) is list)
                archive = "generic-%02d" % index
                if item["entries"] == [{"path": ".", "kind": "absent"}]:
                    need(absent(generic, archive))
                else:
                    archive_path = os.path.join(root,
                        "var/lib/aegis-auto-uninstall/backup/generic", archive)
                    actual = _generic_tree_manifest(archive_path, [0, 0])
                    need(_generic_contents(actual) == _generic_contents(item["entries"]))
        finally:
            os.close(generic)
        return sha(canonical(manifest))
    finally:
        os.close(backup)


def backup_generic_roots(fd, *, root="/", owner=0, group=0, passive=False):
    """Fsync a retained, bounded copy before the generic purge's first effect."""
    intent = (passive_intent(fd, owner=owner, group=group) if passive else
              read(fd, owner=owner, group=group)[0])
    backup = _ensure_backup(fd, owner=owner, group=group)
    try:
        if not absent(backup, "generic-manifest.json"):
            return verify_generic_backup(fd, root=root, owner=owner, group=group, passive=passive)
        if not absent(backup, "generic"):
            generic = os.open("generic", os.O_RDONLY | os.O_DIRECTORY |
                              os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=backup)
            try:
                raw = leaf(generic, "manifest.json", owner=owner, group=group,
                           maximum=4 << 20)
                publish(backup, "generic-manifest.json", raw, owner=owner,
                        group=group, maximum=4 << 20)
            finally:
                os.close(generic)
            return verify_generic_backup(fd, root=root, owner=owner, group=group, passive=passive)
        if not absent(backup, "pending-generic"):
            rename_noreplace(backup, "pending-generic",
                             "failed-" + secrets.token_hex(16))
            os.fsync(backup)
        os.mkdir("pending-generic", 0o700, dir_fd=backup)
        os.fsync(backup)
        pending = os.path.join(root,
            "var/lib/aegis-auto-uninstall/backup/pending-generic")
        roots = []
        budget = [0, 0]
        for index, source in enumerate(_generic_roots(passive=passive)):
            source_path = os.path.join(root, source.lstrip("/"))
            entries = _generic_tree_manifest(source_path, budget)
            roots.append({"source": source, "entries": entries})
            if entries != [{"path": ".", "kind": "absent"}]:
                target = pending + ("/generic-%02d" % index)
                if entries[0]["kind"] == "file":
                    shutil.copy2(source_path, target, follow_symlinks=False)
                else:
                    shutil.copytree(source_path, target, symlinks=True)
                need(_generic_contents(_generic_tree_manifest(target, [0, 0])) ==
                     _generic_contents(entries))
        for item in roots:
            source_path = os.path.join(root, item["source"].lstrip("/"))
            need(_generic_tree_manifest(source_path, [0, 0]) == item["entries"])
        manifest = {"schema": "aegis_auto_v2_generic_purge_backup_v1",
                    "intent_sha256": sha(canonical(intent)), "roots": roots}
        raw = canonical(manifest)
        need(len(raw) <= 4 << 20)
        pending_fd = os.open("pending-generic", os.O_RDONLY | os.O_DIRECTORY |
                             os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=backup)
        try:
            for directory, _dirs, files, walked_fd in os.fwalk(pending):
                for name in files:
                    held = os.open(name, os.O_RDONLY | os.O_NOFOLLOW |
                                   os.O_CLOEXEC, dir_fd=walked_fd)
                    try:
                        os.fsync(held)
                    finally:
                        os.close(held)
                os.fsync(walked_fd)
            publish(pending_fd, "manifest.json", raw, owner=owner, group=group,
                    maximum=4 << 20)
            os.fsync(pending_fd)
        finally:
            os.close(pending_fd)
        rename_noreplace(backup, "pending-generic", "generic")
        os.fsync(backup)
        # Publish a top-level manifest only after the copy is durably named.
        publish(backup, "generic-manifest.json", raw, owner=owner, group=group,
                maximum=4 << 20)
        return verify_generic_backup(fd, root=root, owner=owner, group=group, passive=passive)
    finally:
        os.close(backup)


def retire_boot_store(version):
    """Retire exact BOOT members via held nofollow directories after backup."""
    verify_generic_handoff(version)
    journal = directory()
    try:
        _intent, phases = read(journal)
        backup = _ensure_backup(journal, create=False)
        try:
            manifest = strict_json(leaf(backup, "generic-manifest.json", maximum=4 << 20))
            owner_raw = leaf(backup, "manifest.json", maximum=4 << 20)
            owners = strict_json(owner_raw)
            need(type(owners) is dict and set(owners) ==
                 {"schema", "owners", "entries"} and
                 sha(owner_raw) == phases[2][0]["backup_manifest_sha256"] and
                 len(owners["owners"]) <= 64)
            verify_backup(journal, tuple(owners["owners"]), sha(owner_raw))
            store_entries = [entry for entry in owners["entries"] if
                             entry["path"] == "etc/aegis-auto-terminal-store.json"]
            need(len(store_entries) == 1)
            store_entry = store_entries[0]
            store_config = None
            if store_entry["kind"] == "file":
                etc = os.open("etc", os.O_RDONLY | os.O_DIRECTORY |
                              os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=backup)
                try:
                    store_raw = leaf(etc, "aegis-auto-terminal-store.json", maximum=4096)
                finally:
                    os.close(etc)
                need(sha(store_raw) == store_entry["sha256"])
                store_config = strict_json(store_raw)
                need(type(store_config) is dict and
                     store_config.get("schema") == "aegis_auto_terminal_boot_store_v1" and
                     store_config.get("boot_store_dir") == "aegis-auto-terminal")
        finally:
            os.close(backup)
        matches = [item for item in manifest["roots"]
                   if item["source"] == BOOT_STORE_ROOT]
        need(len(matches) == 1)
        expected = matches[0]["entries"]
        archive_index = manifest["roots"].index(matches[0])
        archive = ("/var/lib/aegis-auto-uninstall/backup/generic/generic-%02d"
                   % archive_index)
        if expected == [{"path": ".", "kind": "absent"}]:
            need(not os.path.exists(archive) and not os.path.islink(archive))
        else:
            need(_generic_tree_manifest(archive, [0, 0]) == expected)
        boot = os.open("/boot", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW |
                       os.O_CLOEXEC)
        try:
            root_dev = os.stat("/").st_dev
            boot_info = os.fstat(boot)
            need(boot_info.st_uid == boot_info.st_gid == 0 and
                 boot_info.st_dev != root_dev and
                 not stat.S_IMODE(boot_info.st_mode) & 0o022)
            if store_config is not None:
                need(store_config["boot_dev"] ==
                     f"{os.major(boot_info.st_dev)}:{os.minor(boot_info.st_dev)}")
            if absent(boot, "aegis-auto-terminal"):
                return True
            store = os.open("aegis-auto-terminal", os.O_RDONLY | os.O_DIRECTORY |
                            os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=boot)
            try:
                info = os.fstat(store)
                need(info.st_dev == boot_info.st_dev and
                     info.st_uid == info.st_gid == 0 and
                     stat.S_IMODE(info.st_mode) == 0o700 and
                     expected != [{"path": ".", "kind": "absent"}])
                need(store_config is not None or len(os.listdir(store)) == 0)
                reference = {entry["path"]: entry for entry in expected}
                need(len(reference) == len(expected) and
                     set(reference) == {"."} | {entry["path"] for entry in expected
                                                if entry["kind"] == "file"} and
                     reference["."]["kind"] == "directory")
                names = sorted(os.listdir(store))
                need(len(names) <= 128)
                for name in names:
                    need(name in reference and
                         re.fullmatch(r"terminal-[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}-[0-9a-f]{32}\.json", name))
                    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW |
                                 os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=store)
                    try:
                        actual = os.fstat(fd)
                        need(stat.S_ISREG(actual.st_mode) and actual.st_nlink == 1 and
                             actual.st_uid == actual.st_gid == 0 and
                             stat.S_IMODE(actual.st_mode) == 0o600 and
                             actual.st_size == reference[name]["size"] and
                             actual.st_size <= 4096)
                        digest = hashlib.sha256()
                        while chunk := os.read(fd, 4096):
                            digest.update(chunk)
                        after = os.fstat(fd)
                        named = os.stat(name, dir_fd=store, follow_symlinks=False)
                        need(digest.hexdigest() == reference[name]["sha256"] and
                             (after.st_dev, after.st_ino, after.st_size,
                              after.st_mtime_ns, after.st_ctime_ns) ==
                             (actual.st_dev, actual.st_ino, actual.st_size,
                              actual.st_mtime_ns, actual.st_ctime_ns) ==
                             (named.st_dev, named.st_ino, named.st_size,
                              named.st_mtime_ns, named.st_ctime_ns))
                    finally:
                        os.close(fd)
                need(os.fstat(store).st_dev == info.st_dev and
                     os.fstat(store).st_ino == info.st_ino and
                     os.fstat(boot).st_dev == boot_info.st_dev and
                     os.fstat(boot).st_ino == boot_info.st_ino)
                for name in names:
                    os.unlink(name, dir_fd=store)
                os.fsync(store)
            finally:
                os.close(store)
            os.rmdir("aegis-auto-terminal", dir_fd=boot)
            os.fsync(boot)
            need(absent(boot, "aegis-auto-terminal"))
            return True
        finally:
            os.close(boot)
    finally:
        os.close(journal)


if __name__ == "__main__":
    try:
        need(len(sys.argv) == 3 and sys.argv[1] in
             ("verify-package-handoff", "verify-generic-handoff",
              "retire-boot-store"))
        if sys.argv[1] == "verify-generic-handoff":
            verify_generic_handoff(sys.argv[2])
        elif sys.argv[1] == "retire-boot-store":
            retire_boot_store(sys.argv[2])
        else:
            verify_package_handoff(sys.argv[2])
    except (Refused, OSError, ValueError, KeyError, TypeError):
        print("AUTO V2 uninstall package handoff refused", file=sys.stderr)
        raise SystemExit(1)


def _open_components(root_fd, parts, *, owner, group, create=False):
    current = os.dup(root_fd)
    try:
        for part in parts:
            if create:
                try:
                    os.mkdir(part, 0o700, dir_fd=current)
                    os.fsync(current)
                except FileExistsError:
                    pass
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW |
                            os.O_CLOEXEC, dir_fd=current)
            checked_dir(child, owner, group)
            os.close(current)
            current = child
        return current
    except BaseException:
        os.close(current)
        raise


def _source_entry(root_fd, relative, *, owner, group, depth=0, budget=None):
    need(depth <= 16 and budget is not None and budget[0] < 16384)
    budget[0] += 1
    parts = relative.split("/")
    need(all(part not in ("", ".", "..") for part in parts))
    try:
        parent = _open_components(root_fd, parts[:-1], owner=owner, group=group)
    except FileNotFoundError:
        return [{"path": relative, "kind": "absent"}]
    try:
        try:
            before = os.stat(parts[-1], dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError:
            return [{"path": relative, "kind": "absent"}]
        need(before.st_uid == owner and before.st_gid == group and
             not stat.S_ISLNK(before.st_mode) and
             not stat.S_IMODE(before.st_mode) & 0o022)
        common = {"path": relative, "mode": stat.S_IMODE(before.st_mode),
                  "device": before.st_dev, "inode": before.st_ino}
        if stat.S_ISDIR(before.st_mode):
            child = os.open(parts[-1], os.O_RDONLY | os.O_DIRECTORY |
                            os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
            try:
                need((os.fstat(child).st_dev, os.fstat(child).st_ino) ==
                     (before.st_dev, before.st_ino))
                names = sorted(os.listdir(child))
                need(len(names) <= 4096)
                entries = [{**common, "kind": "directory",
                            "names_sha256": sha(canonical(names))}]
                for name in names:
                    need(name not in (".", "..") and "/" not in name)
                    entries.extend(_source_entry(root_fd, relative + "/" + name,
                                                 owner=owner, group=group,
                                                 depth=depth + 1, budget=budget))
            finally:
                os.close(child)
        else:
            need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and
                 0 <= before.st_size <= 512 << 20 and
                 budget[1] + before.st_size <= 1024 << 20)
            child = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW |
                            os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=parent)
            try:
                digest = hashlib.sha256()
                size = 0
                while chunk := os.read(child, 65536):
                    size += len(chunk)
                    need(size <= before.st_size)
                    digest.update(chunk)
                after = os.fstat(child)
                named = os.stat(parts[-1], dir_fd=parent, follow_symlinks=False)
                fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
                need(size == before.st_size and all(
                    getattr(before, field) == getattr(item, field)
                    for item in (after, named) for field in fields))
                budget[1] += size
                entries = [{**common, "kind": "file", "size": size,
                            "sha256": digest.hexdigest()}]
            finally:
                os.close(child)
        return entries
    finally:
        os.close(parent)


def source_manifest(paths, *, root="/", owner=0, group=0):
    """Bounded exact inventory of fixed owners, including private subtrees."""
    need(type(paths) in (tuple, list) and 1 <= len(paths) <= 64 and
         len(set(paths)) == len(paths))
    root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW |
                      os.O_CLOEXEC)
    try:
        checked_dir(root_fd, owner, group)
        budget = [0, 0]
        entries = []
        for path in paths:
            need(type(path) is str and path.startswith("/") and
                 all(part not in ("", ".", "..") for part in path[1:].split("/")))
            entries.extend(_source_entry(root_fd, path[1:], owner=owner,
                                         group=group, budget=budget))
        return {"schema": "aegis_auto_v2_uninstall_backup_manifest_v1",
                "owners": list(paths), "entries": entries}
    finally:
        os.close(root_fd)


def _ensure_backup(fd, *, owner, group, create=True):
    if create:
        try:
            os.mkdir("backup", 0o700, dir_fd=fd)
            os.fsync(fd)
        except FileExistsError:
            pass
    backup = os.open("backup", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW |
                     os.O_CLOEXEC, dir_fd=fd)
    checked_dir(backup, owner, group)
    need(stat.S_IMODE(os.fstat(backup).st_mode) == 0o700)
    return backup


def _copy_entry(source_root, backup, entry, *, owner, group):
    relative = entry["path"]
    parts = relative.split("/")
    target_parent = _open_components(backup, parts[:-1], owner=owner,
                                     group=group, create=True)
    try:
        if entry["kind"] == "absent":
            need(absent(target_parent, parts[-1]))
            return
        if entry["kind"] == "directory":
            try:
                os.mkdir(parts[-1], 0o700, dir_fd=target_parent)
                os.fsync(target_parent)
            except FileExistsError:
                pass
            child = os.open(parts[-1], os.O_RDONLY | os.O_DIRECTORY |
                            os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=target_parent)
            try:
                checked_dir(child, owner, group)
                need(stat.S_IMODE(os.fstat(child).st_mode) == 0o700)
            finally:
                os.close(child)
            return
        source_parent = _open_components(source_root, parts[:-1],
                                         owner=owner, group=group)
        try:
            source = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW |
                             os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=source_parent)
            try:
                info = os.fstat(source)
                need(stat.S_ISREG(info.st_mode) and info.st_uid == owner and
                     info.st_gid == group and info.st_nlink == 1 and
                     (info.st_dev, info.st_ino, info.st_size) ==
                     (entry["device"], entry["inode"], entry["size"]))
                if not absent(target_parent, parts[-1]):
                    need(sha(leaf(target_parent, parts[-1], owner=owner,
                                  group=group, maximum=512 << 20)) == entry["sha256"])
                    return
                pending = "pending-" + parts[-1]
                if not absent(target_parent, pending):
                    old = os.stat(pending, dir_fd=target_parent,
                                  follow_symlinks=False)
                    need(stat.S_ISREG(old.st_mode) and old.st_uid == owner and
                         old.st_gid == group and old.st_nlink == 1 and
                         stat.S_IMODE(old.st_mode) == 0o600)
                    failed = "failed-" + secrets.token_hex(16)
                    rename_noreplace(target_parent, pending, failed)
                    os.fsync(target_parent)
                target = os.open(pending, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                                 os.O_NOFOLLOW | os.O_CLOEXEC, 0o600,
                                 dir_fd=target_parent)
                try:
                    digest = hashlib.sha256()
                    size = 0
                    while chunk := os.read(source, 65536):
                        size += len(chunk)
                        need(size <= entry["size"])
                        digest.update(chunk)
                        view = memoryview(chunk)
                        while view:
                            view = view[os.write(target, view):]
                    need(size == entry["size"] and digest.hexdigest() == entry["sha256"])
                    os.fsync(target)
                finally:
                    os.close(target)
                os.fsync(target_parent)
                rename_noreplace(target_parent, pending, parts[-1])
                os.fsync(target_parent)
            finally:
                os.close(source)
        finally:
            os.close(source_parent)
    finally:
        os.close(target_parent)


def backup_owners(journal_fd, paths, *, root="/", owner=0, group=0):
    """Copy protected rollback material before guard recovery removes owners."""
    manifest = source_manifest(paths, root=root, owner=owner, group=group)
    raw = canonical(manifest)
    backup = _ensure_backup(journal_fd, owner=owner, group=group)
    source_root = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW |
                          os.O_CLOEXEC)
    try:
        for entry in manifest["entries"]:
            _copy_entry(source_root, backup, entry, owner=owner, group=group)
        need(source_manifest(paths, root=root, owner=owner, group=group) == manifest)
        publish(backup, "manifest.json", raw, owner=owner, group=group,
                maximum=4 << 20)
        return sha(raw)
    finally:
        os.close(source_root)
        os.close(backup)


def verify_backup(journal_fd, paths, expected_sha, *, owner=0, group=0):
    """Authenticate every retained owner byte without relying on live owners."""
    need(type(expected_sha) is str and HEX.fullmatch(expected_sha) is not None)
    backup = _ensure_backup(journal_fd, owner=owner, group=group, create=False)
    try:
        raw = leaf(backup, "manifest.json", owner=owner, group=group,
                   maximum=4 << 20)
        need(sha(raw) == expected_sha)
        manifest = strict_json(raw)
        need(type(manifest) is dict and set(manifest) == {"schema", "owners", "entries"} and
             manifest["schema"] == "aegis_auto_v2_uninstall_backup_manifest_v1" and
             manifest["owners"] == list(paths) and type(manifest["entries"]) is list)
        names = set()
        for entry in manifest["entries"]:
            need(type(entry) is dict and type(entry.get("path")) is str and
                 entry["path"] not in names and entry["kind"] in
                 ("absent", "file", "directory"))
            names.add(entry["path"])
            parts = entry["path"].split("/")
            need(all(part not in ("", ".", "..") for part in parts))
            try:
                parent = _open_components(backup, parts[:-1], owner=owner, group=group)
            except FileNotFoundError:
                need(entry["kind"] == "absent")
                continue
            try:
                if entry["kind"] == "absent":
                    need(absent(parent, parts[-1]))
                    continue
                info = os.stat(parts[-1], dir_fd=parent, follow_symlinks=False)
                need(info.st_uid == owner and info.st_gid == group and
                     not stat.S_ISLNK(info.st_mode))
                if entry["kind"] == "directory":
                    need(stat.S_ISDIR(info.st_mode) and
                         stat.S_IMODE(info.st_mode) == 0o700)
                else:
                    need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and
                         stat.S_IMODE(info.st_mode) == 0o600 and
                         info.st_size == entry["size"])
                    child = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW |
                                    os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=parent)
                    try:
                        digest = hashlib.sha256()
                        size = 0
                        while chunk := os.read(child, 65536):
                            size += len(chunk)
                            need(size <= entry["size"])
                            digest.update(chunk)
                        need(size == entry["size"] and
                             digest.hexdigest() == entry["sha256"])
                    finally:
                        os.close(child)
            finally:
                os.close(parent)
        return manifest
    finally:
        os.close(backup)


def retire_owners(journal_fd, paths, backup_sha, *,
                  guard_removed=(), root="/", owner=0, group=0):
    """Move exact remaining owners into retained backup after guard release.

    Missing owner paths are admitted only if absent at backup time or if the
    guard's own protected recovery removed one of its fixed unit files. The
    caller must have proven guard disarm and all actors quiescent first.
    """
    intent, phases = read(journal_fd, owner=owner, group=group)
    need(len(phases) == 5 and phases[3][0]["state"] == "guard-released" and
         phases[4][0]["state"] == "actors-quiescent" and
         phases[2][0]["backup_manifest_sha256"] == backup_sha)
    manifest = verify_backup(journal_fd, paths, backup_sha, owner=owner, group=group)
    top = {entry["path"]: entry for entry in manifest["entries"]
           if "/" + entry["path"] in paths}
    need(set(top) == {path[1:] for path in paths})
    allowed_removed = set(guard_removed)
    need(allowed_removed <= {
        "/etc/systemd/system/aegis-device-egress-guard.service",
        "/etc/systemd/system/aegis-foreign-policy-monitor.service",
        "/etc/systemd/system/aegis-auto-clean-shutdown.service",
        "/etc/systemd/system/aegis-device-dhcp-refresh.service",
        "/etc/systemd/system/aegis-device-dhcp-refresh.timer",
    })
    backup = _ensure_backup(journal_fd, owner=owner, group=group, create=False)
    root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW |
                      os.O_CLOEXEC)
    try:
        checked_dir(root_fd, owner, group)
        # Retire unit sources first; keep control and its boot gate until last.
        order = tuple(range(5, len(paths))) + tuple(range(1, 5)) + (0,)
        for index in order:
            path = paths[index]
            entry = top[path[1:]]
            parts = path[1:].split("/")
            try:
                parent = _open_components(root_fd, parts[:-1], owner=owner,
                                          group=group)
            except FileNotFoundError:
                parent = None
            try:
                current = None if parent is None or absent(parent, parts[-1]) else os.stat(
                    parts[-1], dir_fd=parent, follow_symlinks=False)
                retired = f"retired-{index:02d}"
                archived = None if absent(backup, retired) else os.stat(
                    retired, dir_fd=backup, follow_symlinks=False)
                if current is not None:
                    need(archived is None and entry["kind"] != "absent" and
                         current.st_uid == owner and current.st_gid == group and
                         not stat.S_ISLNK(current.st_mode) and
                         stat.S_IMODE(current.st_mode) == entry["mode"] and
                         (stat.S_ISDIR(current.st_mode) if entry["kind"] == "directory"
                          else stat.S_ISREG(current.st_mode) and current.st_nlink == 1))
                    if entry["kind"] == "file" and path != \
                            "/var/lib/aegis-install/client/device-guard.conf":
                        source = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW |
                                         os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=parent)
                        try:
                            digest = hashlib.sha256()
                            while chunk := os.read(source, 65536):
                                digest.update(chunk)
                            need(digest.hexdigest() == entry["sha256"])
                        finally:
                            os.close(source)
                    rename_noreplace(parent, parts[-1], retired, target_fd=backup)
                    os.fsync(parent)
                    os.fsync(backup)
                    archived = os.stat(retired, dir_fd=backup,
                                       follow_symlinks=False)
                    need((current.st_dev, current.st_ino) ==
                         (archived.st_dev, archived.st_ino))
                    status = "moved"
                elif archived is not None:
                    need(entry["kind"] != "absent" and archived.st_uid == owner and
                         archived.st_gid == group and not stat.S_ISLNK(archived.st_mode))
                    status = "moved"
                else:
                    need(entry["kind"] == "absent" or path in allowed_removed)
                    status = "absent-at-admission" if entry["kind"] == "absent" else \
                             "removed-by-guard"
                receipt = {"schema": "aegis_auto_v2_uninstall_retired_owner_v1",
                           "index": index, "path": path, "status": status,
                           "backup_manifest_sha256": backup_sha,
                           "device": archived.st_dev if archived is not None else None,
                           "inode": archived.st_ino if archived is not None else None}
                publish(backup, f"retired-{index:02d}.json", canonical(receipt),
                        owner=owner, group=group)
            finally:
                if parent is not None:
                    os.close(parent)
        for path in paths:
            parts = path[1:].split("/")
            try:
                parent = _open_components(root_fd, parts[:-1], owner=owner,
                                          group=group)
            except FileNotFoundError:
                continue
            try:
                need(absent(parent, parts[-1]))
            finally:
                os.close(parent)
        return sha(canonical({"intent_sha256": sha(canonical(intent)),
                              "backup_manifest_sha256": backup_sha,
                              "retired": list(paths)}))
    finally:
        os.close(root_fd)
        os.close(backup)


def archive_completed(fd, *, root="/", owner=0, group=0):
    """Retain backup/receipts and clear the live barrier after full purge."""
    intent, phases = read(fd, owner=owner, group=group)
    need(len(phases) == len(STATES) and not absent(fd, "completed.json"))
    destination = "aegis-auto-uninstall-completed-" + intent["nonce"]
    location = {"schema": "aegis_auto_v2_uninstall_retained_location_v1",
                "intent_sha256": sha(canonical(intent)), "directory": destination}
    publish(fd, "retained-location.json", canonical(location),
            owner=owner, group=group)
    read(fd, owner=owner, group=group)
    root = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW |
                   os.O_CLOEXEC)
    try:
        lib = _open_components(root, ("var", "lib"), owner=owner, group=group)
        try:
            source_stat = os.fstat(fd)
            named = os.stat("aegis-auto-uninstall", dir_fd=lib,
                            follow_symlinks=False)
            need((source_stat.st_dev, source_stat.st_ino) ==
                 (named.st_dev, named.st_ino) and absent(lib, destination))
            rename_noreplace(lib, "aegis-auto-uninstall", destination)
            os.fsync(lib)
            retired = os.stat(destination, dir_fd=lib, follow_symlinks=False)
            need((retired.st_dev, retired.st_ino) ==
                 (source_stat.st_dev, source_stat.st_ino))
            return destination
        finally:
            os.close(lib)
    finally:
        os.close(root)


def retire_auto_root(journal_fd, *, root="/", owner=0, group=0):
    """Move the remaining release/cache namespace after control was retired."""
    intent, phases = read(journal_fd, owner=owner, group=group)
    need(len(phases) >= 6 and phases[5][0]["state"] == "owners-archived")
    backup = _ensure_backup(journal_fd, owner=owner, group=group, create=False)
    root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW |
                      os.O_CLOEXEC)
    try:
        lib = _open_components(root_fd, ("var", "lib"), owner=owner, group=group)
        try:
            present = not absent(lib, "aegis-auto")
            retired = not absent(backup, "retired-auto-root")
            need(present != retired)
            if present:
                manifest = source_manifest(("/var/lib/aegis-auto",), root=root,
                                           owner=owner, group=group)
                raw = canonical(manifest)
                publish(backup, "auto-root-manifest.json", raw, owner=owner,
                        group=group, maximum=4 << 20)
                before = os.stat("aegis-auto", dir_fd=lib, follow_symlinks=False)
                need(stat.S_ISDIR(before.st_mode) and before.st_uid == owner and
                     before.st_gid == group and not stat.S_IMODE(before.st_mode) & 0o022)
                rename_noreplace(lib, "aegis-auto", "retired-auto-root",
                                 target_fd=backup)
                os.fsync(lib)
                os.fsync(backup)
                after = os.stat("retired-auto-root", dir_fd=backup,
                                follow_symlinks=False)
                need((after.st_dev, after.st_ino) == (before.st_dev, before.st_ino))
            raw = leaf(backup, "auto-root-manifest.json", owner=owner,
                       group=group, maximum=4 << 20)
            manifest = strict_json(raw)
            need(manifest["schema"] == "aegis_auto_v2_uninstall_backup_manifest_v1" and
                 manifest["owners"] == ["/var/lib/aegis-auto"] and
                 not absent(backup, "retired-auto-root") and
                 absent(lib, "aegis-auto"))
            # The moved tree retains each original inode. Rewalk under its new
            # pathname and compare every entry except the pathname prefix.
            moved = source_manifest((
                "/var/lib/aegis-auto-uninstall/backup/retired-auto-root",),
                root=root, owner=owner, group=group)
            old_prefix = "var/lib/aegis-auto"
            new_prefix = "var/lib/aegis-auto-uninstall/backup/retired-auto-root"
            expected = [{**entry, "path": entry["path"].replace(
                old_prefix, new_prefix, 1)} for entry in manifest["entries"]]
            need(moved["entries"] == expected)
            receipt = {"schema": "aegis_auto_v2_uninstall_auto_root_archive_v1",
                       "intent_sha256": sha(canonical(intent)),
                       "manifest_sha256": sha(raw),
                       "retired_inode": os.stat("retired-auto-root", dir_fd=backup,
                                                follow_symlinks=False).st_ino}
            publish(backup, "auto-root-retired.json", canonical(receipt),
                    owner=owner, group=group)
            return sha(canonical(receipt))
        finally:
            os.close(lib)
    finally:
        os.close(root_fd)
        os.close(backup)
