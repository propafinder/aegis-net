#!/usr/bin/env python3
"""Complete server entry, stopped at its first original binary preflight.

No build, selected ABI/private protocol, purge, installation, or service runs.
The full real-reader/floor regression is separate evidence. POSIX owned-child
observation is required; absence is an environment error, never a green skip.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import stat
import subprocess
import tempfile
import time


class Invalid(RuntimeError):
    pass


def need(ok, reason):
    if not ok:
        raise Invalid("INVALID portable preflight fixture: " + reason)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def private(path, data):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as stream:
        stream.write(data)


def record(path, value):
    private(path, (json.dumps(value, indent=2) + "\n").encode())


def complete_function(source, name):
    start = re.search(r"^" + re.escape(name) + r"\(\) \{\n", source, re.M)
    need(start is not None, "actual function declaration")
    following = re.search(r"^[A-Za-z_][A-Za-z0-9_]*\(\) \{\n", source[start.end():], re.M)
    limit = start.end() + following.start() if following else len(source)
    end = source.rfind("\n}\n", start.end(), limit)
    need(end >= start.end(), "complete shell closing brace")
    body = source[start.start():end + 2] + "\n"
    need('print_systemd_followup "aegis-server.service"' in body, "complete original server tail")
    return body


def owned(case, argv, env):
    """Existing repository WNOWAIT pattern; retain leader through group signals.

    Signals target the fresh owned group before reaping. Confirmation here is
    direct-leader custody, not an assertion about escaped descendants or OS
    preemption. The exercised hook path consists of shell builtins only.
    """
    out, err = case / "stdout.log", case / "stderr.log"
    child, status, problem = None, None, None
    observed = False
    signals = []
    cutoff = time.monotonic() + 12
    with os.fdopen(os.open(out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as stdout, \
            os.fdopen(os.open(err, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as stderr:
        try:
            child = subprocess.Popen(argv, env=env, stdin=subprocess.DEVNULL,
                                     stdout=stdout, stderr=stderr, start_new_session=True)
            record(case / "started.json", {"owned_pid": child.pid, "observation_seconds": 12})
            while time.monotonic() < cutoff:
                if os.waitid(os.P_PID, child.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT):
                    observed = True
                    break
                time.sleep(0.005)
            if not observed:
                problem = "observation_cutoff"
        except BaseException as error:
            problem = type(error).__name__
        finally:
            if child is not None:
                cleanup_cutoff = time.monotonic() + 4
                for value in (signal.SIGTERM, signal.SIGKILL):
                    try:
                        os.killpg(child.pid, value)
                        signals.append({"signal": int(value), "result": "sent"})
                    except ProcessLookupError:
                        signals.append({"signal": int(value), "result": "group_absent"})
                    except PermissionError:
                        signals.append({"signal": int(value), "result": "permission_refused"})
                        # An observed Darwin singleton zombie can refuse signals.
                        # This qualification does not prove group quiescence.
                        if not observed:
                            problem = problem or "group_signal_unconfirmed"
                    except BaseException as error:
                        problem = problem or type(error).__name__
                try:
                    remaining = cleanup_cutoff - time.monotonic()
                    need(remaining > 0, "original cleanup cutoff")
                    status = child.wait(timeout=remaining)
                except BaseException as error:
                    problem = problem or type(error).__name__
    execution = {"exit_code": status, "observed_before_cleanup": observed,
                 "owned_leader_reaped": status is not None, "problem": problem,
                 "group_signal_attempts": signals, "stdout_sha256": digest(out),
                 "stderr_sha256": digest(err), "observation_seconds": 12, "cleanup_seconds": 4,
                 "descendant_quiescence_claimed": False}
    record(case / "execution.json", execution)
    need(observed and status is not None and problem is None, "owned child observation/cleanup")
    return execution, out.read_bytes(), err.read_bytes()


HOOKS = r'''
resolve_existing_install_choice() { printf '%s\n' "$FIXTURE_CHOICE"; }
apply_existing_install_choice() { printf '%s\0%s\0' "$1" "$2" >> "$FIXTURE_APPLY"; return 0; }
install_binary() { printf '%s\0%s\0%s\0%s\0' "$1" "$2" "$3" "${4:-install}" >> "$FIXTURE_PREFLIGHT"; return 86; }
command_not_found_handle() { printf 'unexpected\0%s\0' "$1" >> "$FIXTURE_UNEXPECTED"; return 99; }
install_server_role
'''


CASES = (
    ("existing_env_and_unit", "both", "upgrade", "0", "active", "refuse"),
    ("existing_env_only", "env", "upgrade", "0", "active", "refuse"),
    ("existing_unit_only", "unit", "upgrade", "0", "active", "refuse"),
    ("dangling_env", "dangling_env", "upgrade", "0", "active", "refuse"),
    ("dangling_unit", "dangling_unit", "upgrade", "0", "active", "refuse"),
    ("asset_conflict_without_detected_install", "both", "none", "0", "active", "refuse"),
    ("cancel_before_gate", "both", "cancel", "0", "active", "cancel"),
    ("cancel_even_with_force", "both", "cancel", "1", "active", "cancel"),
    ("force_reaches_original_preflight", "both", "upgrade", "1", "active", "preflight"),
    ("reinstall_reaches_original_preflight", "both", "reinstall", "0", "active", "preflight"),
    ("conflict_free_reaches_original_preflight", "none", "upgrade", "0", "active", "preflight"),
)


def nul(path):
    if not path.exists():
        return []
    values = path.read_bytes().split(b"\0")
    need(values[-1] == b"", "complete hook record")
    return [value.decode() for value in values[:-1]]


def leaf_snapshot(path):
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return None
    if stat.S_ISLNK(metadata.st_mode):
        return {"type": "symlink", "target": os.readlink(path)}
    need(stat.S_ISREG(metadata.st_mode), "owned fixture regular asset")
    return {"type": "regular", "sha256": digest(path), "mode": stat.S_IMODE(metadata.st_mode)}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-root", default=os.environ.get("AEGIS_TEST_INSTALLER_ROOT"))
    parser.add_argument("--bash", default=os.environ.get("AEGIS_TEST_BASH", "bash"))
    parser.add_argument("--receipt-dir")
    args = parser.parse_args()
    need(os.name == "posix" and all(hasattr(os, name) for name in
         ("waitid", "P_PID", "WEXITED", "WNOHANG", "WNOWAIT")), "POSIX nonreaping observation required")
    need(signal.getsignal(signal.SIGCHLD) == signal.SIG_DFL, "exclusive child ownership required")
    source_root = Path(args.source_root).resolve(strict=True) if args.source_root else Path(__file__).resolve().parents[1]
    source_path = source_root / "install.sh"
    need(stat.S_ISREG(source_path.lstat().st_mode), "actual checkout installer")
    source_sha = digest(source_path)
    body = complete_function(source_path.read_text(), "install_server_role")
    bash_path = shutil.which(args.bash)
    need(bash_path is not None, "actual Bash dependency required")
    bash = Path(bash_path).resolve(strict=True)
    need(stat.S_ISREG(bash.lstat().st_mode) and os.access(bash, os.X_OK), "actual executable Bash")
    bash_sha = digest(bash)
    output = Path(args.receipt_dir).absolute() if args.receipt_dir else Path(tempfile.mkdtemp(prefix="aegis-server-preflight-evidence-"))
    if args.receipt_dir:
        need(not output.exists() and not output.is_symlink(), "fresh receipt directory")
        output.mkdir(mode=0o700)
    output.chmod(0o700)
    record(output / "source-identity.json", {"install_sha256": source_sha, "body_sha256": hashlib.sha256(body.encode()).hexdigest(),
           "fixture_sha256": digest(Path(__file__).resolve()), "bash_sha256": bash_sha})
    rows = []
    with tempfile.TemporaryDirectory(prefix="private-working-", dir=output) as temporary:
        work = Path(temporary)
        work.chmod(0o700)
        entry = work / "complete-server-entry.sh"
        private(entry, ("set -euo pipefail\n" + body + HOOKS).encode())
        for name, assets, choice, force, active, expectation in CASES:
            case = work / name
            case.mkdir(mode=0o700)
            logs = output / name
            logs.mkdir(mode=0o700)
            env_dir, units_dir = case / "env", case / "units"
            env_dir.mkdir(mode=0o700)
            units_dir.mkdir(mode=0o700)
            env_asset, unit_asset = env_dir / "aegis-server", units_dir / "aegis-server.service"
            for path, selected in ((env_asset, assets in ("both", "env")), (unit_asset, assets in ("both", "unit"))):
                if selected:
                    private(path, b"owned old service asset\n")
            if assets == "dangling_env":
                env_asset.symlink_to(case / "missing-env-target")
            if assets == "dangling_unit":
                unit_asset.symlink_to(case / "missing-unit-target")
            before = [leaf_snapshot(env_asset), leaf_snapshot(unit_asset)]
            preflight, apply, unexpected = case / "preflight", case / "apply", case / "unexpected"
            env = {key: os.environ[key] for key in ("PATH", "LANG", "LC_ALL") if key in os.environ}
            env.update(PREFIX=str(case / "prefix"), CONFIG_DIR=str(case / "config"), STATE_DIR=str(case / "state"),
                       SYSTEMD_DIR=str(units_dir), ENV_DIR=str(env_dir), FORCE=force,
                       FIXTURE_CHOICE=choice, FIXTURE_PREFLIGHT=str(preflight), FIXTURE_APPLY=str(apply),
                       FIXTURE_UNEXPECTED=str(unexpected), ROOT=str(case / "not-used-package"), SOURCE_LAYOUT="0")
            execution, stdout, stderr = owned(logs, [str(bash), str(entry)], env)
            need(digest(source_path) == source_sha and digest(bash) == bash_sha, "source/tool drift")
            first = ["aegis-server", "aegis-server", str(case / "prefix/bin"), "preflight"]
            hook, applied = nul(preflight), nul(apply)
            preserved = before == [leaf_snapshot(env_asset), leaf_snapshot(unit_asset)]
            need(preserved and not unexpected.exists(), "fixture boundary or unrelated continuation")
            code = execution["exit_code"]
            valid_old_checkpoint = code == 86 and hook == first and not applied and not stdout and not stderr
            if expectation == "refuse":
                asset = env_asset if env_asset.exists() or env_asset.is_symlink() else unit_asset
                wanted = ("Refusing to overwrite existing file without --force: " + str(asset) + "\n").encode()
                good = code == 1 and not hook and not applied and stdout == b"" and stderr == wanted
                need(good or valid_old_checkpoint, "unrelated refusal/control outcome")
                cause = "none" if good else "first_preflight_reached_before_known_service_refusal"
            elif expectation == "cancel":
                need(code == 0 and not hook and applied == ["server", "cancel"] and not stdout and not stderr,
                     "cancel ordering changed")
                cause = "none"
            else:
                need(valid_old_checkpoint, "original first preflight ordering changed")
                cause = "none"
            rows.append({"case": name, "status": "PASS" if cause == "none" else "FAIL", "cause": cause,
                         "exit_code": code, "old_assets_preserved": preserved, "owned_leader_reaped": True})
            print("AUDIT79_PORTABLE case=" + name + " status=" + rows[-1]["status"] + " cause=" + cause, flush=True)
    record(output / "fixture-result.json", {"schema": "audit79_portable_gate_v1", "cases": rows,
           "install_sha256": source_sha, "body_sha256": hashlib.sha256(body.encode()).hexdigest(),
           "scope": "complete server function stopped at its first original preflight",
           "real_abi_or_private_protocol_or_build_acceptance": False, "purge_or_floor_acceptance": False,
           "native_service_acceptance": False, "descendant_quiescence_claimed": False})
    return 0 if all(row["status"] == "PASS" for row in rows) else 1


if __name__ == "__main__":
    raise SystemExit(main())
