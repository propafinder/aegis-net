"""Disposable Linux-only integration test for actual root preflight/drop.

Run as root in the isolated VM, never on a live authority.
"""
import hashlib
import json
import os
from pathlib import Path
import runpy
import shutil
import stat
import subprocess
import sys
import time


assert os.geteuid() == 0
HELPER = Path(__file__).with_name("bootstrap_bundle_status_lock.py")
BASE = Path(f"/run/aegis-b09-root-run-{os.getpid()}")
BIN = str(BASE / "server-bin")
GID = 989
UID = 999


def shasum(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def server_child():
    os.setgroups([])
    os.setgid(GID)
    os.setuid(UID)


def case_run(case, server_pid, config, store, parent, machine, pin_path):
    if case == "pin_mode":
        pin_path.chmod(0o644)
    if case == "exe_mismatch":
        replacement = BASE / "replacement-bin"
        shutil.copy2(BIN, replacement)
        replacement.chmod(0o755)
        os.replace(replacement, BIN)
    env = runpy.run_path(str(HELPER))
    scope = env["run"].__globals__
    scope["service_pid"] = lambda: server_pid
    original_store = scope["read_store_identity"]
    seen = []

    def guarded_store(*args, **kwargs):
        seen.append("store")
        assert os.getuid() == UID and os.geteuid() == UID
        assert os.getgid() == GID and os.getegid() == GID
        assert os.getgroups() == []
        status = Path("/proc/self/status").read_text()
        caps = next(line.split()[1] for line in status.splitlines() if line.startswith("CapEff:"))
        assert int(caps, 16) == 0
        try:
            os.setuid(0)
        except PermissionError:
            pass
        else:
            raise AssertionError("regained_root")
        return original_store(*args, **kwargs)

    scope["read_store_identity"] = guarded_store
    if case == "restart":
        second = subprocess.Popen([BIN, "-c", "import time; time.sleep(60)",
                                   "--config", str(config)], preexec_fn=server_child)
        calls = iter((server_pid, second.pid))
        scope["service_pid"] = lambda: next(calls)
    else:
        second = None
    if case == "drop_failure":
        scope["os"].setuid = lambda _uid: (_ for _ in ()).throw(OSError("injected_drop_failure"))
    argv = [str(HELPER), "--pin-file", str(pin_path)]
    sys.argv = argv
    expected = "DRY_RUN_READY" if case == "ready" else "REFUSED"
    try:
        scope["run"]()
    except (scope["Refused"], OSError) as error:
        assert expected == "REFUSED", (case, type(error).__name__, str(error))
        assert not seen, (case, "unexpected_store_access")
        print(case, "REFUSED", type(error).__name__, str(error), flush=True)
    else:
        assert expected == "DRY_RUN_READY" and seen, (case, seen)
        assert not Path(str(store) + ".lock").exists()
        print(case, "DRY_RUN_READY", "post-drop-store-guard-pass", flush=True)
    finally:
        if second is not None:
            second.terminate()
            second.wait(timeout=5)


try:
    BASE.mkdir(mode=0o755)
    shutil.copy2(Path(sys.executable).resolve(), BIN)
    Path(BIN).chmod(0o755)
    parent = BASE / "data"
    parent.mkdir(mode=0o700)
    os.chown(parent, UID, GID)
    store = parent / "tokens.json"
    store.write_bytes(b"synthetic-no-token")
    os.chown(store, UID, GID)
    store.chmod(0o600)
    config = BASE / "server.toml"
    config.write_text('[bundle_endpoint]\nenabled = true\ntoken_store_path = "' + str(store) + '"\n')
    os.chown(config, 0, GID)
    config.chmod(0o640)
    machine = shasum("/etc/machine-id")
    pin_path = BASE / "pin.json"
    pin_path.write_text(json.dumps({
        "hostname": __import__("socket").gethostname(),
        "machine_id_sha256": machine,
        "source_commit": "0" * 40,
        "server_sha256": shasum(BIN),
        "server_bin": BIN,
        "service": "aegis-fixture.service",
        "config": str(config),
        "store": str(store),
        "uid": UID,
        "gid": GID,
        "config_sha256": shasum(config),
        "store_dev": store.stat().st_dev,
        "store_ino": store.stat().st_ino,
        "parent_dev": parent.stat().st_dev,
        "parent_ino": parent.stat().st_ino,
    }))
    pin_path.chmod(0o600)
    server = subprocess.Popen([BIN, "-c", "import time; time.sleep(60)",
                               "--config", str(config)], preexec_fn=server_child)
    time.sleep(0.2)
    assert server.poll() is None
    for case in ("ready", "restart", "drop_failure", "pin_mode", "exe_mismatch"):
        pid = os.fork()
        if pid == 0:
            try:
                case_run(case, server.pid, config, store, parent, machine, pin_path)
            except BaseException as error:
                print(case, "FAIL", type(error).__name__, str(error), flush=True)
                os._exit(1)
            os._exit(0)
        _, status = os.waitpid(pid, 0)
        if case == "pin_mode":
            pin_path.chmod(0o600)
        assert os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0, (case, status)
    assert store.read_bytes() == b"synthetic-no-token"
    assert not Path(str(store) + ".lock").exists()
    print("ROOT_RUN_5_OF_5_PASS", flush=True)
finally:
    if "server" in locals():
        server.terminate()
        server.wait(timeout=5)
    shutil.rmtree(BASE)
