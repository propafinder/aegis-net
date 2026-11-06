#!/usr/bin/env bash
# Exercise both real standalone download helpers without external networking.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
python3 - "${ROOT}" <<'PY'
import http.server
import contextlib
import io
import hashlib
import importlib.util
import shutil
import stat
import json
import os
import re
import signal
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

root = Path(sys.argv[1])
helpers = {}
for name in ("bootstrap-install.sh", "install.sh"):
    source = (root / name).read_text()
    helpers[name] = re.search(r'^download_url\(\) \{\n.*?^\}', source, re.M | re.S)[0]


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        try:
            if self.path == "/before":
                time.sleep(3)
                return
            if self.path == "/error":
                self.send_error(503)
                return
            payload = b"complete fixture" if self.path == "/ok" else b""
            if self.path in ("/partial", "/during"):
                payload = b"partial"
            self.send_response(200)
            self.send_header("Content-Length", str(100 if self.path in ("/partial", "/during") else len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            self.wfile.flush()
            if self.path == "/during":
                time.sleep(3)
        except (BrokenPipeError, ConnectionResetError):
            pass


stub_code = '''import json, os, pathlib, sys, time
args = sys.argv[1:]
out = args[args.index("-o") + 1] if "-o" in args else args[args.index("-qO") + 1]
mode = os.environ["AEGIS_DOWNLOAD_STUB_MODE"]
if os.environ.get("AEGIS_DOWNLOAD_STUB_PID"):
    pathlib.Path(os.environ["AEGIS_DOWNLOAD_STUB_PID"]).write_text(str(os.getpid()))
if mode not in ("before", "fail-before", "empty"):
    pathlib.Path(out).write_bytes(b"fixture bytes")
with open(os.environ["AEGIS_DOWNLOAD_STUB_LOG"], "a") as log:
    print(json.dumps(args), file=log)
if mode in ("before", "during"):
    time.sleep(5)
if mode in ("partial-failure", "fail-before"):
    raise SystemExit(28)
'''

with tempfile.TemporaryDirectory(prefix="aegis-download-contract-") as temp:
    work = Path(temp)
    tools = work / "tools"
    tools.mkdir()
    (tools / "python3").symlink_to(sys.executable)
    log = work / "calls.jsonl"
    destination = work / "output"
    env = {**os.environ, "PATH": str(tools), "AEGIS_DOWNLOAD_CONNECT_TIMEOUT_SECONDS": "1",
           "AEGIS_DOWNLOAD_TOTAL_TIMEOUT_SECONDS": "10", "AEGIS_DOWNLOAD_STUB_LOG": str(log),
           "BUNDLE_CACERT_PIN": "", "BUNDLE_INSECURE": "0"}

    def run(source, helper, url, expected=None, success=False, extra=None, budget=10, case=""):
        context = f"{source}/{case} (transfer budget={budget}s)"
        destination.write_bytes(b"stale output must not be reused")
        started = time.monotonic()
        try:
            result = subprocess.run(
                ["/bin/bash", "-c", helper + '\ndownload_url "$1" "$2"\n', "download-contract", url, str(destination)],
                env={**env, **(extra or {}), "AEGIS_DOWNLOAD_TOTAL_TIMEOUT_SECONDS": str(budget)},
                capture_output=True, text=True, timeout=budget + 5,
            )
        except subprocess.TimeoutExpired:
            # Avoid TimeoutExpired's command rendering, which includes the URL.
            raise AssertionError(f"{context}: outer watchdog exceeded {budget + 5}s") from None
        elapsed = time.monotonic() - started
        assert elapsed < budget + 3, f"{context}: elapsed={elapsed:.3f}s escaped bounded transfer"
        if expected is not None:
            assert result.returncode == expected, (context, "actual", result.returncode, "expected", expected, "elapsed", round(elapsed, 3), result.stderr)
        if success:
            assert result.returncode == 0 and destination.stat().st_size > 0, (context, result.stderr)
        else:
            assert result.returncode != 0 and not destination.exists(), (context, result.stderr)
        assert not list(work.glob("output.part.*")), f"{context}: partial download survived failure/commit"
        assert "private-fixture-token" not in result.stdout + result.stderr, f"{context}: diagnostic exposed URL"
        return result

    def cancel_during_spawn(source, helper, signum):
        # Execute the actual Python helper, delivering the signal precisely
        # after a real child session exists but before Popen returns ownership.
        # The substituted child only sleeps locally; fixture cleanup is bounded
        # even when this regression reappears in the production helper.
        body = helper.split("<<'PY'\n", 1)[1].rsplit("\nPY\n}", 1)[0]
        real_popen = subprocess.Popen
        old_argv = sys.argv
        old_signals = {sig: signal.getsignal(sig) for sig in (signal.SIGTERM, signal.SIGINT)}
        child = None
        stderr = io.StringIO()

        def spawn_then_cancel(_command, **kwargs):
            nonlocal child
            child = real_popen([sys.executable, "-c", "import time; time.sleep(5)"], **kwargs)
            os.kill(os.getpid(), signum)
            return child

        destination.write_bytes(b"stale output must not be reused")
        sys.argv = ["download-helper", "file:///unused-local-fixture?token=private-fixture-token",
                    str(destination), "1", "2", "", "0"]
        subprocess.Popen = spawn_then_cancel
        started = time.monotonic()
        try:
            with contextlib.redirect_stderr(stderr):
                try:
                    exec(compile(body, source + ":download_url", "exec"), {})
                except SystemExit as result:
                    assert result.code == 128 + signum, (source, result.code, stderr.getvalue())
                else:
                    raise AssertionError("cancellation during spawn was ignored")
            assert time.monotonic() - started < 2, "deferred cancellation waited for the transfer budget"
            assert child is not None, "spawn cancellation fixture never created its child"
            # Do not poll/wait here: that could reap a zombie and hide missing
            # production cleanup. The helper must already have killed and reaped.
            assert child.returncode is not None, "downloader was not reaped after spawn cancellation"
            try:
                os.kill(child.pid, 0)
            except ProcessLookupError:
                pass
            else:
                raise AssertionError("downloader survived cancellation during spawn")
            assert "reason=cancelled" in stderr.getvalue()
            assert "private-fixture-token" not in stderr.getvalue()
            assert not destination.exists() and not list(work.glob("output.part.*"))
        finally:
            subprocess.Popen = real_popen
            sys.argv = old_argv
            for sig, handler in old_signals.items():
                signal.signal(sig, handler)
            if child is not None:
                if child.poll() is None:
                    os.killpg(child.pid, signal.SIGKILL)
                child.wait(timeout=2)

    for source, helper in (("bootstrap-install.sh", helpers["bootstrap-install.sh"]),):
        for signum in (signal.SIGTERM, signal.SIGINT):
            cancel_during_spawn(source, helper, signum)
        for downloader in ("curl", "wget"):
            path = tools / downloader
            path.write_text("#!" + sys.executable + "\n" + stub_code)
            path.chmod(0o755)
            for mode, expected in (("ok", 0), ("empty", 65), ("fail-before", 28),
                                   ("partial-failure", 28), ("before", 124), ("during", 124)):
                # Status/cleanup checks need scheduling headroom under a busy
                # CI build. Only deliberate 5s stalls exercise the narrow 3s
                # hard limit; do not turn a timeout into acceptable success.
                budget = 3 if mode in ("before", "during") else 10
                case = f"{downloader}/{mode}"
                context = f"{source}/{case}"
                log.write_text("")
                run(source, helper, "https://fixture.invalid/bundle?token=private-fixture-token", expected,
                    success=expected == 0, extra={"AEGIS_DOWNLOAD_STUB_MODE": mode}, budget=budget, case=case)
                calls = [json.loads(line) for line in log.read_text().splitlines()]
                # Stub logs after any partial write, before the 5s stall. A
                # timeout before that checkpoint cannot prove the intended stage.
                assert len(calls) == 1, f"{context}: stub stage missing or one-time URL retried"
                if downloader == "curl":
                    assert calls[0][calls[0].index("--retry") + 1] == "0", context
                    assert calls[0][-2] == "--", f"{context}: URL must be data, not a downloader option"
                    assert calls[0][calls[0].index("--connect-timeout") + 1] == "1", context
                    assert calls[0][calls[0].index("--max-time") + 1] == str(budget), context
                else:
                    assert "--tries=1" in calls[0] and "--timeout=1" in calls[0], context
                    assert calls[0][-2] == "--", f"{context}: URL must be data, not a downloader option"
            # Cancellation of the installer group must reap the separately
            # supervised transfer group, not only unlink its output.
            pid_file = work / "downloader.pid"
            pid_file.unlink(missing_ok=True)
            cancelled = subprocess.Popen(
                ["/bin/bash", "-c", helper + '\ndownload_url "$1" "$2"\n',
                 "download-contract", "https://fixture.invalid/bundle?token=private-fixture-token", str(destination)],
                env={**env, "AEGIS_DOWNLOAD_STUB_MODE": "before", "AEGIS_DOWNLOAD_STUB_PID": str(pid_file)},
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, start_new_session=True,
            )
            deadline = time.monotonic() + 5
            while not pid_file.exists() and time.monotonic() < deadline:
                time.sleep(0.01)
            assert pid_file.exists(), "downloader never reached cancellation checkpoint"
            downloader_pid = int(pid_file.read_text())
            os.killpg(cancelled.pid, signal.SIGTERM)
            stdout, stderr = cancelled.communicate(timeout=5)
            assert cancelled.returncode != 0
            assert "reason=cancelled" in stderr
            assert "private-fixture-token" not in stdout + stderr
            try:
                os.kill(downloader_pid, 0)
            except ProcessLookupError:
                pass
            else:
                raise AssertionError("downloader survived cancellation")
            assert not destination.exists() and not list(work.glob("output.part.*"))
            if source == "install.sh":
                log.write_text("")
                result = run(source, helper, "https://fixture.invalid/bundle?token=private-fixture-token",
                             0 if downloader == "curl" else 1, success=downloader == "curl",
                             extra={"BUNDLE_CACERT_PIN": "fixture-pin", "AEGIS_DOWNLOAD_STUB_MODE": "ok"}, case=f"{downloader}/pin")
                if downloader == "curl":
                    assert "--pinnedpubkey" in json.loads(log.read_text())
                else:
                    assert log.read_text() == "" and "spki_pin_requires_curl" in result.stderr
            path.unlink()

        # No curl/wget in PATH: exercise the actual urllib branch against only
        # an ephemeral loopback server. No firewall/service/host changes.
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        server.daemon_threads = True
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            base = f"http://127.0.0.1:{server.server_port}"
            run(source, helper, base + "/ok", 0, success=True, case="urllib/ok")
            run(source, helper, base + "/empty", 65, case="urllib/empty")
            for endpoint in ("/error", "/partial", "/before", "/during"):
                run(source, helper, base + endpoint, budget=3 if endpoint in ("/before", "/during") else 10,
                    case="urllib" + endpoint)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)
        fixture = work / "local-file"
        fixture.write_bytes(b"local fixture")
        run(source, helper, fixture.as_uri(), 0, success=True, case="file/ok")
        run(source, helper, (work / "missing").as_uri(), 1, case="file/missing")
        if source == "install.sh":
            result = run(source, helper, "https://fixture.invalid/bundle", 1,
                         extra={"BUNDLE_CACERT_PIN": "fixture-pin"}, case="urllib/pin")
            assert "spki_pin_requires_curl" in result.stderr
        print(f"PASS: {source}: curl/wget stub statuses, total budgets, no retry, spawn/cancellation cleanup, localhost urllib/file and pin gates")

    # The installer now delegates to the real Rust private-file consumer. The
    # bootstrap's complete legacy Python loop above remains unchanged. The old
    # install Python pre-Popen hook/urllib fallback no longer exists: this owner
    # is tested through actual child creation/cancellation and explicit refusal.
    selected = os.environ.get("AEGIS_TEST_SECRET_CLIENT")
    if selected:
        input_client = Path(selected).resolve(strict=True)
    else:
        assert all(os.environ.get(key) for key in ("RUNNER_TEMP", "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT", "GITHUB_SHA")), "INVALID actual prebuilt client required"
        spec = importlib.util.spec_from_file_location("local_copy_mode_fixture", root / "scripts/test-installer-secret-local-copy-mode-contract.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        prebuild = Path(os.environ["RUNNER_TEMP"]) / f"installer-source-prebuild-{os.environ['GITHUB_RUN_ID']}-{os.environ['GITHUB_RUN_ATTEMPT']}"
        input_client = module.retained_prebuild_client(prebuild, root, os.environ["GITHUB_SHA"])
    assert input_client.is_file() and os.access(input_client, os.X_OK), "INVALID real client required"
    client = work / "aegis-client"
    binary_digest = hashlib.sha256(input_client.read_bytes()).hexdigest()
    shutil.copyfile(input_client, client)
    client.chmod(0o700)
    assert binary_digest == hashlib.sha256(client.read_bytes()).hexdigest() == hashlib.sha256(input_client.read_bytes()).hexdigest(), "INVALID actual client copy custody"
    version = subprocess.run([str(client), "profile", "installer-secret", "version"],
                             capture_output=True, text=True, timeout=5)
    assert version.returncode == 0 and version.stdout.strip() == "installer-secret-v1", "INVALID actual reader protocol"
    rust_env = {**env, "PREFLIGHT_CLIENT_BINARY": str(client)}
    records = work / "private-url-records"
    records.mkdir(mode=0o700)
    record_number = 0

    def private_record(value, mode=0o600):
        global record_number
        record_number += 1
        path = records / str(record_number)
        with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as stream:
            stream.write(value.encode())
        path.chmod(mode)
        return path

    rust_stub = r"""import hashlib,json,os,pathlib,stat,sys,time
args = sys.argv[1:]
metadata = os.fstat(0)
assert stat.S_ISREG(metadata.st_mode) and metadata.st_mode & 0o7777 == 0o600
record = sys.stdin.buffer.read(16385)
assert len(record) <= 16384
assert b'private-fixture-token' in record
assert all('private-fixture-token' not in item for item in args)
out = args[args.index('-o') + 1] if '-o' in args else args[args.index('-qO') + 1]
mode = os.environ['AEGIS_DOWNLOAD_STUB_MODE']
if os.environ.get('AEGIS_DOWNLOAD_STUB_PID'):
    pathlib.Path(os.environ['AEGIS_DOWNLOAD_STUB_PID']).write_text(str(os.getpid()))
with open(os.environ['AEGIS_DOWNLOAD_STUB_LOG'], 'a') as log:
    print(json.dumps({'args':args,'stdin_sha256':hashlib.sha256(record).hexdigest(),
                      'stdin_is_private_regular':True,'synthetic_source_only_in_stdin':True}), file=log)
if mode not in ('before','fail-before','empty'):
    pathlib.Path(out).write_bytes(b'fixture bytes')
if mode in ('before','during'):
    time.sleep(5)
if mode in ('partial-failure','fail-before'):
    raise SystemExit(28)
"""

    def rust_run(value, expected=None, success=False, extra=None, budget=10, case="", private_mode=0o600, existing=False):
        context = f"install.sh/{case} (transfer budget={budget}s)"
        destination.unlink(missing_ok=True)
        if existing:
            destination.write_bytes(b"stale output must not be reused")
            destination.chmod(0o600)
        record = private_record(value, private_mode)
        started = time.monotonic()
        try:
            result = subprocess.run(
                ["/bin/bash", "-c", helpers["install.sh"] + '\ndownload_url "$1" "$2"\n',
                 "private-download-contract", str(record), str(destination)],
                env={**rust_env, **(extra or {}), "AEGIS_DOWNLOAD_TOTAL_TIMEOUT_SECONDS": str(budget)},
                capture_output=True, text=True, timeout=budget + 5,
            )
        except subprocess.TimeoutExpired:
            raise AssertionError(f"{context}: outer watchdog exceeded {budget + 5}s") from None
        elapsed = time.monotonic() - started
        assert elapsed < budget + 3, f"{context}: elapsed={elapsed:.3f}s escaped bounded transfer"
        if expected is not None:
            assert result.returncode == expected, (context, "actual", result.returncode, "expected", expected, "elapsed", round(elapsed, 3), result.stderr)
        if existing:
            assert result.returncode != 0 and destination.read_bytes() == b"stale output must not be reused"
            assert destination.stat().st_mode & 0o7777 == 0o600
        elif success:
            assert result.returncode == 0 and destination.stat().st_size > 0, (context, result.stderr)
            assert destination.stat().st_mode & 0o7777 == 0o600
        else:
            assert result.returncode != 0 and not destination.exists(), (context, result.stderr)
        assert not list(work.glob("output.part.*")) and not list(work.glob(".tmp*")), f"{context}: partial download survived failure/commit"
        assert "private-fixture-token" not in result.stdout + result.stderr, f"{context}: diagnostic exposed URL"
        return result

    def rust_calls():
        return [json.loads(line) for line in log.read_text().splitlines()]

    def rust_cancel(signum, downloader):
        # This actual Rust owner is observed after a real transfer child starts.
        # It is not the removed Python injection-before-Popen-return coverage.
        destination.unlink(missing_ok=True)
        pid_file = work / "rust-downloader.pid"
        pid_file.unlink(missing_ok=True)
        record = private_record("https://fixture.invalid/one-time?token=private-fixture-token")
        stdout_file, stderr_file = work / "rust-cancel.stdout", work / "rust-cancel.stderr"
        stdout_file.unlink(missing_ok=True)
        stderr_file.unlink(missing_ok=True)
        observed = False
        child = None
        with stdout_file.open("xb") as stdout, stderr_file.open("xb") as stderr:
            stdout_file.chmod(0o600)
            stderr_file.chmod(0o600)
            try:
                child = subprocess.Popen(
                    [str(client), "profile", "installer-secret", "fetch", "--input", str(record),
                     "--output", str(destination), "--connect-seconds", "1", "--total-seconds", "10"],
                    env={**rust_env, "AEGIS_DOWNLOAD_STUB_MODE": "before", "AEGIS_DOWNLOAD_STUB_PID": str(pid_file)},
                    stdout=stdout, stderr=stderr, stdin=subprocess.DEVNULL, start_new_session=True)
                deadline = time.monotonic() + 5
                while not pid_file.exists() and time.monotonic() < deadline:
                    time.sleep(0.01)
                assert pid_file.exists(), "real downloader never reached cancellation checkpoint"
                downloader_pid = int(pid_file.read_text())
                os.killpg(child.pid, signum)
                deadline = time.monotonic() + 5
                while time.monotonic() < deadline:
                    if os.waitid(os.P_PID, child.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT):
                        observed = True
                        break
                    time.sleep(0.005)
                assert observed, "Rust owner did not finish cancellation within original observation bound"
            finally:
                if child is not None:
                    cleanup = time.monotonic() + 2
                    if not observed:
                        # Exclusive child ownership retains identity through the last signal.
                        try:
                            os.killpg(child.pid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                    while time.monotonic() < cleanup and child.poll() is None:
                        time.sleep(0.005)
                    assert child.returncode is not None, "INVALID cancellation child cleanup unconfirmed"
        assert child.returncode == 128 + signum
        assert "reason=cancelled" in stderr_file.read_text()
        assert "private-fixture-token" not in stdout_file.read_text() + stderr_file.read_text()
        try:
            os.kill(downloader_pid, 0)
        except ProcessLookupError:
            pass
        else:
            raise AssertionError("downloader survived actual Rust cancellation")
        assert not destination.exists() and not list(work.glob(".tmp*")) and not list(work.glob("output.part.*"))
        assert len(rust_calls()) == 1, "one-time transfer child was missing or retried"

    assert hasattr(os, "waitid") and hasattr(os, "WNOWAIT"), "INVALID owned wait API required"
    assert signal.getsignal(signal.SIGCHLD) == signal.SIG_DFL, "INVALID exclusive child ownership required"
    for downloader in ("curl", "wget"):
        path = tools / downloader
        path.write_text("#!" + sys.executable + "\n" + rust_stub)
        path.chmod(0o755)
        for mode, expected in (("ok", 0), ("empty", 65), ("fail-before", 28),
                               ("partial-failure", 28), ("before", 124), ("during", 124)):
            budget = 3 if mode in ("before", "during") else 10
            log.write_text("")
            log.chmod(0o600)
            rust_run("https://fixture.invalid/one-time?token=private-fixture-token", expected,
                     success=expected == 0, extra={"AEGIS_DOWNLOAD_STUB_MODE": mode},
                     budget=budget, case=f"{downloader}/{mode}")
            calls = rust_calls()
            assert len(calls) == 1, "stub stage missing or one-time URL retried"
            args = calls[0]["args"]
            assert calls[0]["stdin_is_private_regular"] and calls[0]["synthetic_source_only_in_stdin"]
            assert all("private-fixture-token" not in value and "https://" not in value for value in args)
            if downloader == "curl":
                assert args[0] == "-q" and args[args.index("--retry") + 1] == "0"
                assert args[args.index("--connect-timeout") + 1] == "1" and args[args.index("--max-time") + 1] == str(budget)
                assert args[args.index("--proto") + 1] == "=https" and args[args.index("--proto-redir") + 1] == "=https"
                assert args[args.index("--config") + 1] == "-"
            else:
                assert "--no-config" in args and "--tries=1" in args and "--timeout=1" in args
                assert "--max-redirect=0" in args and "--input-file=-" in args
        for signum in (signal.SIGTERM, signal.SIGINT):
            log.write_text("")
            rust_cancel(signum, downloader)
        log.write_text("")
        result = rust_run("https://fixture.invalid/one-time?token=private-fixture-token",
                          0 if downloader == "curl" else 2, success=downloader == "curl",
                          extra={"BUNDLE_CACERT_PIN": "fixture-pin", "AEGIS_DOWNLOAD_STUB_MODE": "ok"}, case=f"{downloader}/pin")
        if downloader == "curl":
            assert "--pinnedpubkey" in rust_calls()[0]["args"] and len(rust_calls()) == 1
        else:
            assert log.read_text() == "" and "spki_pin_requires_curl" in result.stderr
        for name, value, options, expected, reason in (
            ("public-private-record", "https://fixture.invalid/one-time?token=private-fixture-token", {"private_mode": 0o644}, 2, "private_input_rejected"),
            ("existing-output", "https://fixture.invalid/one-time?token=private-fixture-token", {"existing": True}, 1, "output_already_exists"),
            ("http-refusal", "http://fixture.invalid/one-time?token=private-fixture-token", {}, 2, "unsupported_url_scheme"),
        ):
            log.write_text("")
            result = rust_run(value, expected, extra={"AEGIS_DOWNLOAD_STUB_MODE": "ok"}, case=f"{downloader}/{name}", **options)
            assert reason in result.stderr and not rust_calls(), "refusal reached transport child"
        path.unlink()
    log.write_text("")
    result = rust_run("https://fixture.invalid/one-time?token=private-fixture-token", 2, case="no-tool/refusal")
    assert "curl_or_wget_required" in result.stderr and not rust_calls(), "removed urllib fallback attempted transfer"
    local = work / "rust-local-file"
    local.write_bytes(b"local fixture")
    rust_run(local.as_uri(), 0, success=True, case="file/ok")
    assert destination.read_bytes() == b"local fixture"
    rust_run((work / "rust-missing").as_uri(), 1, case="file/missing")
    print("PASS: install.sh real Rust/private inputs: actual curl/wget recording children, original budgets/no retry/cancel/reap; private/existing/no-tool refusal and local copy")
PY
