#!/usr/bin/env python3
"""Bounded local startup series for a loopback-only aegis-server config."""

import argparse
import importlib.util
import json
import math
import os
from pathlib import Path
import resource
import signal
import subprocess
import time
import tomllib

COLLECTOR_PATH = Path(__file__).with_name("collect-optimizer-startup.py")
SPEC = importlib.util.spec_from_file_location("startup_collector", COLLECTOR_PATH)
COLLECTOR = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(COLLECTOR)


def exited_unreaped(child: subprocess.Popen) -> bool:
    """Observe leader exit while retaining its PID and process-group identity."""
    status = os.waitid(os.P_PID, child.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
    return status is not None and status.si_pid == child.pid


def signal_owned_group(child: subprocess.Popen, sig: signal.Signals) -> bool:
    try:
        os.killpg(child.pid, sig)
    except ProcessLookupError:
        return False
    except PermissionError:
        # Darwin reports EPERM when only the unreaped zombie leader remains.
        # A live owned leader must never turn a denied signal into a PASS.
        if not exited_unreaped(child):
            raise
        return True
    return False


def finish(child: subprocess.Popen, sig: signal.Signals) -> int:
    # All group signals precede wait(): reaping the leader can free its PGID.
    denied = signal_owned_group(child, sig)
    deadline = time.monotonic() + (0 if sig == signal.SIGKILL else 5)
    while time.monotonic() < deadline and not exited_unreaped(child):
        time.sleep(0.05)
    # A leader can exit while descendants remain in its owned process group.
    # Keep its zombie PID reserved until after this last group signal.
    denied |= signal_owned_group(child, signal.SIGKILL)
    result = child.wait(timeout=3)
    if denied:
        # Probe only: no signal after reaping. EPERM may otherwise conceal a
        # live descendant that changed UID, and is not proof of cleanup.
        try:
            os.killpg(child.pid, 0)
        except ProcessLookupError:
            pass
        else:
            raise RuntimeError("owned process group cleanup unconfirmed")
    return result


def cap_child_log() -> None:
    resource.setrlimit(resource.RLIMIT_FSIZE,
                       (COLLECTOR.MAX_LOG_BYTES, COLLECTOR.MAX_LOG_BYTES))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("config", type=Path)
    parser.add_argument("output_dir", type=Path)
    parser.add_argument("--runs", type=int, default=10)
    parser.add_argument("--short-dwell", type=float, default=2.0)
    parser.add_argument("--last-dwell", type=float, default=60.0)
    parser.add_argument("--ready-timeout", type=float, default=15.0)
    args = parser.parse_args()
    if (not 1 <= args.runs <= 20
            or not math.isfinite(args.short_dwell) or not 0 < args.short_dwell <= 600
            or not math.isfinite(args.last_dwell) or not 0 < args.last_dwell <= 600
            or not math.isfinite(args.ready_timeout)
            or not 0.1 <= args.ready_timeout <= 30.0):
        raise SystemExit("invalid bounded series")
    with args.config.open("rb") as stream:
        config = tomllib.load(stream)
    allowed_top = {"listen", "cert", "key", "fallback", "limits", "transport"}
    allowed_transport = {"quic_listen", "inner_tls", "authenticated_shaping"}
    if (set(config) - allowed_top
            or set(config.get("transport", {})) - allowed_transport
            or config.get("fallback", "close") != "close"):
        raise SystemExit("series requires the inert loopback fixture config shape")
    inner_tls = config.get("transport", {}).get("inner_tls", {})
    if isinstance(inner_tls, dict) and inner_tls.get("device_registry") is not None:
        raise SystemExit("series refuses an operator-managed device registry")
    if config.get("listen") != "127.0.0.1:0" or config.get("transport", {}).get(
        "quic_listen"
    ) != "127.0.0.1:0":
        raise SystemExit("series requires ephemeral loopback TCP and QUIC listeners")
    args.output_dir.mkdir(mode=0o700, parents=False, exist_ok=False)
    results = []
    for index in range(1, args.runs + 1):
        log_path = args.output_dir / f"run-{index:02d}.log"
        with log_path.open("x", encoding="utf-8") as stream:
            child = subprocess.Popen(
                [str(args.binary), "--config", str(args.config), "--optimizer-startup-report"],
                stdout=stream,
                stderr=subprocess.STDOUT,
                env={**os.environ, "AEGIS_NO_BANNER": "1", "RUST_LOG": "info"},
                start_new_session=True,
                preexec_fn=cap_child_log,
            )
            ready = False
            log_refusal = None
            started = time.monotonic()
            try:
                deadline = started + args.ready_timeout
                while time.monotonic() < deadline:
                    if log_path.stat().st_size >= COLLECTOR.MAX_LOG_BYTES:
                        log_refusal = "saturated run log"
                        break
                    try:
                        COLLECTOR.parse_run(log_path)
                    except (ValueError, UnicodeError):
                        pass
                    else:
                        ready = True
                        break
                    if exited_unreaped(child):
                        break
                    time.sleep(0.05)
                dwell = args.last_dwell if index == args.runs else args.short_dwell
                alive_during_dwell = ready
                until = time.monotonic() + dwell
                while ready and time.monotonic() < until:
                    if log_path.stat().st_size >= COLLECTOR.MAX_LOG_BYTES:
                        log_refusal = "saturated run log"
                        alive_during_dwell = False
                        break
                    if exited_unreaped(child):
                        alive_during_dwell = False
                        break
                    time.sleep(min(0.1, max(0.0, until - time.monotonic())))
                if ready and exited_unreaped(child):
                    alive_during_dwell = False
                exit_code = finish(child, signal.SIGTERM)
                if log_path.stat().st_size >= COLLECTOR.MAX_LOG_BYTES:
                    log_refusal = "saturated run log"
                if log_refusal is not None:
                    ready = False
                if ready:
                    try:
                        COLLECTOR.parse_run(log_path)
                    except (ValueError, UnicodeError) as error:
                        ready = False
                        log_refusal = str(error)
                results.append({
                    "run": index,
                    "ready_and_reported": ready,
                    "alive_during_dwell": alive_during_dwell,
                    "dwell_seconds": dwell,
                    "exit_code": exit_code,
                    "elapsed_seconds": round(time.monotonic() - started, 3),
                    "log": log_path.name,
                    "log_refusal": log_refusal,
                })
            finally:
                if child.returncode is None:
                    finish(child, signal.SIGKILL)
        if not all((ready, alive_during_dwell, exit_code == 0)):
            break
    print(json.dumps(results, indent=2))
    if len(results) != args.runs or any(
        not row["ready_and_reported"] or not row["alive_during_dwell"]
        or row["exit_code"] != 0 for row in results
    ):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
