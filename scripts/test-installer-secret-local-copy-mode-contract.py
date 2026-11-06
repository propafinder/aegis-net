#!/usr/bin/env python3
"""Real parent fetch/local worker under child-only umasks; no network/install."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tempfile
import time


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def private(path, data):
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as stream:
        stream.write(data)
    path.chmod(0o600)


def execute(case, binary, url_file, output, mask):
    out, err = case / "stdout.log", case / "stderr.log"
    command = [str(binary), "profile", "installer-secret", "fetch", "--input", str(url_file),
               "--output", str(output), "--connect-seconds", "1", "--total-seconds", "10"]
    env = {key: os.environ[key] for key in ("PATH", "LANG", "LC_ALL") if key in os.environ}
    env.update(HOME=str(case), TMPDIR=str(case))
    child = None
    observed = False
    problem = None
    status = None
    attempted = []
    with out.open("xb") as stdout, err.open("xb") as stderr:
        out.chmod(0o600)
        err.chmod(0o600)
        try:
            # Only this fresh process receives the umask. Parent state is untouched.
            child = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr,
                                     env=env, start_new_session=True, preexec_fn=lambda: os.umask(mask))
            deadline = time.monotonic() + 20
            while time.monotonic() < deadline:
                if os.waitid(os.P_PID, child.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT):
                    observed = True
                    break
                time.sleep(0.005)
            if not observed:
                problem = "observation_deadline"
        except BaseException as failure:
            problem = type(failure).__name__
        finally:
            if child is not None:
                # The leader stays reserved until both final group signal attempts.
                # This proves direct-child reaping, not escaped descendant quiescence.
                cleanup_deadline = time.monotonic() + 4
                for sig in (signal.SIGTERM, signal.SIGKILL):
                    try:
                        os.killpg(child.pid, sig)
                        attempted.append(int(sig))
                    except ProcessLookupError:
                        pass
                    except PermissionError:
                        # Darwin may refuse a confirmed exited singleton zombie.
                        # No group quiescence is inferred from this qualification.
                        if not observed:
                            problem = problem or "group_signal_unconfirmed"
                while time.monotonic() < cleanup_deadline:
                    status = child.poll()
                    if status is not None:
                        break
                    time.sleep(0.005)
    record = {"umask": f"{mask:03o}", "rc": status, "observed": observed,
              "owned_leader_reaped": status is not None, "signal_attempts": attempted,
              "problem": problem, "stdout_sha256": digest(out), "stderr_sha256": digest(err)}
    private(case / "execution.json", (json.dumps(record, indent=2) + "\n").encode())
    assert child is not None and status is not None and problem is None, "INVALID process observation/cleanup"
    return status, out.read_bytes(), err.read_bytes()


def retained_prebuild_client(prebuild, source, expected_head):
    # Exact current builder layout, not arbitrary glob or debug/PATH discovery.
    import platform
    import re
    import stat
    import tomllib
    version = tomllib.loads((source / "aegis-server/Cargo.toml").read_text())["package"]["version"]
    assert re.fullmatch(r"[0-9A-Za-z.+-]+", version), "INVALID source package version"
    arch = {"arm64": "aarch64", "amd64": "x86_64"}.get(platform.machine(), platform.machine())
    assert arch in ("x86_64", "aarch64", "armv7l"), "INVALID host architecture"
    target = {"x86_64": "x86_64-unknown-linux-gnu", "aarch64": "aarch64-unknown-linux-gnu",
              "armv7l": "armv7-unknown-linux-gnueabihf"}[arch]
    assert sys.platform == "linux", "INVALID default prebuild requires native Linux host"
    assert re.fullmatch(r"[0-9a-f]{40}", expected_head), "INVALID CI source identity"
    bundle_name = f"aegis-{version}-linux-{arch}"
    bundle = prebuild / bundle_name
    manifest_path = bundle / "bundle.manifest.json"
    metadata = manifest_path.lstat()
    assert stat.S_ISREG(metadata.st_mode) and metadata.st_size <= 2 * 1024 * 1024, "INVALID exact prebuild manifest"
    manifest = json.loads(manifest_path.read_text())
    assert manifest["schema"] == "aegis_release_bundle_manifest_v2", "INVALID prebuild schema"
    assert manifest["bundle_name"] == bundle_name and manifest["version"] == version, "INVALID version binding"
    assert manifest["platform"] == "linux" and manifest["arch"] == arch and manifest["target_triple"] == target, "INVALID host binding"
    assert manifest["git_sha"] == expected_head, "INVALID source head binding"
    assert manifest["cargo_lock_sha256"] == digest(source / "Cargo.lock"), "INVALID lockfile binding"
    entry = manifest["binaries"]["aegis-client"]
    assert entry["path"] == "bin/aegis-client" and entry["path"] in manifest["files"], "INVALID declared client role"
    binary = bundle / entry["path"]
    assert stat.S_ISREG(binary.lstat().st_mode) and os.access(binary, os.X_OK), "INVALID retained executable"
    assert re.fullmatch(r"[0-9a-f]{64}", entry["sha256"]) and digest(binary) == entry["sha256"], "INVALID retained client digest"
    return binary


def main():
    parser = argparse.ArgumentParser()
    inputs = parser.add_mutually_exclusive_group(required=True)
    inputs.add_argument("--client")
    inputs.add_argument("--prebuild-root")
    parser.add_argument("--source-root")
    parser.add_argument("--expected-head")
    parser.add_argument("--receipt-dir")
    args = parser.parse_args()
    assert os.name == "posix" and hasattr(os, "waitid") and hasattr(os, "WNOWAIT"), "INVALID owned wait API unavailable"
    assert signal.getsignal(signal.SIGCHLD) == signal.SIG_DFL, "INVALID exclusive child ownership required"
    if args.client:
        original = Path(args.client).resolve(strict=True)
    else:
        assert args.source_root and args.expected_head, "INVALID prebuild source identity required"
        original = retained_prebuild_client(Path(args.prebuild_root), Path(args.source_root), args.expected_head).resolve(strict=True)
    assert original.is_file() and os.access(original, os.X_OK), "INVALID genuine compiled client required"
    if args.receipt_dir:
        work = Path(args.receipt_dir).absolute()
        work.mkdir(mode=0o700)
    else:
        work = Path(tempfile.mkdtemp(prefix="aegis-local-copy-mode-"))
        work.chmod(0o700)
    work = work.resolve(strict=True)
    before = digest(original)
    binary = work / "aegis-client"
    shutil.copyfile(original, binary)
    binary.chmod(0o700)
    assert before == digest(binary) == digest(original), "INVALID binary copy custody"
    private(work / "identity.json", (json.dumps({"platform": sys.platform, "copied_binary_sha256": before,
            "source_binding_required_from_driver": True, "fixture_umasks": ["022", "077"],
            "parent_process_umask_mutation": False}, indent=2) + "\n").encode())
    rows = []
    for mask in (0o022, 0o077):
        case = work / f"umask-{mask:03o}"
        case.mkdir(mode=0o700)
        source, url_file, output = case / "payload", case / "private-url", case / "download"
        payload = b"actual parent/worker local-copy fixture\x00\xff\n"
        private(source, payload)
        private(url_file, source.as_uri().encode())
        status, stdout, stderr = execute(case, binary, url_file, output, mask)
        assert status == 0, f"actual parent copy failed under umask {mask:03o}; rc={status}"
        assert output.read_bytes() == payload, "local-copy payload changed"
        assert output.stat().st_mode & 0o7777 == 0o600, "published mode is not private"
        assert url_file.read_bytes() == source.as_uri().encode() and url_file.stat().st_mode & 0o7777 == 0o600
        assert not list(case.glob(".tmp*")), "owned staging residue"
        assert source.as_uri().encode() not in stdout + stderr, "private source reflected"
        rows.append({"case": f"actual-parent-worker-umask-{mask:03o}", "result": "PASS"})
    private(work / "receipt.json", (json.dumps({"cases": rows, "native_linux_only_causal_red": sys.platform == "linux",
            "all_existing_worker_admission_and_product_cutoffs_unchanged": True,
            "no_escaped_descendant_quiescence_claim": True}, indent=2) + "\n").encode())
    print(json.dumps({"platform": sys.platform, "PASS": len(rows), "copied_binary_sha256": before}))


if __name__ == "__main__":
    main()
