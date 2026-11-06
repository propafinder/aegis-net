#!/usr/bin/env python3
"""Collect bounded, exact-artifact optimizer startup observations.

This consumes operator-retained logs; it never launches a server or copies logs
into the receipt. An installed-binary and config hash are required because a
local source test cannot stand in for an installed release measurement.
"""

import argparse
import hashlib
import json
import re
import statistics
from pathlib import Path

REPORT = re.compile(
    r"^optimizer_startup attempts=(\d+) completed=(\d+) failures=(\d+) "
    r"total_wall_us=(\d+) total_process_cpu_us=(\d+) "
    r"process_cpu_samples=(\d+) scope=prebind_process_aggregate$"
)
MAX_LOG_BYTES = 2 * 1024 * 1024
MAX_LOG_LINE_CHARS = 16 * 1024
READY_EVENT = re.compile(
    r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+Z  INFO aegis_server: '
    r'required server listeners are ready; application reachability is not yet verified '
    r'event_code="server_ingress_ready" tcp_listener_bound=true '
    r'quic_listener_bound=(true|false) quic_required=(true|false)$'
)


def is_ready_event(line: str) -> bool:
    """Match the exact tracing event emitted after the listeners bind."""
    match = READY_EVENT.fullmatch(line)
    return match is not None and (match[2] == "false" or match[1] == "true")


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def checked_hash(path: Path, expected: str) -> str:
    if not re.fullmatch(r"[0-9a-f]{64}", expected):
        raise ValueError("expected SHA-256 must be 64 lowercase hexadecimal digits")
    actual = sha256(path)
    if actual != expected:
        raise ValueError(f"SHA-256 mismatch for {path.name}")
    return actual


def parse_run(path: Path) -> dict:
    if not path.is_file() or path.stat().st_size > MAX_LOG_BYTES:
        raise ValueError(f"missing or oversized run log: {path.name}")
    raw = path.read_bytes()
    if len(raw) > MAX_LOG_BYTES:
        raise ValueError(f"oversized run log: {path.name}")
    lines = raw.decode("utf-8").splitlines()
    if any(len(line) > MAX_LOG_LINE_CHARS for line in lines):
        raise ValueError(f"oversized run log line: {path.name}")
    report_lines = [line for line in lines if line.startswith("optimizer_startup ")]
    if len(report_lines) != 1 or (match := REPORT.fullmatch(report_lines[0])) is None:
        raise ValueError(f"expected exactly one complete startup report: {path.name}")
    if sum(is_ready_event(line) for line in lines) != 1:
        raise ValueError(f"expected exactly one readiness event: {path.name}")
    attempts, completed, failures, wall_us, cpu_us, cpu_samples = map(
        int, match.groups()
    )
    if attempts < 1 or completed != attempts or failures != 0:
        raise ValueError(f"startup preparation incomplete or refused: {path.name}")
    if cpu_samples not in (0, attempts) or (cpu_samples == 0 and cpu_us != 0):
        raise ValueError(f"inconsistent CPU sample count: {path.name}")
    return {
        "log_sha256": hashlib.sha256(raw).hexdigest(),
        "attempts": attempts,
        "total_wall_us": wall_us,
        "total_process_cpu_us": cpu_us if cpu_samples else None,
    }


def collect(binary: Path, binary_hash: str, config: Path, config_hash: str,
            logs: list[Path], expected_runs: int) -> dict:
    if expected_runs < 1 or len(logs) != expected_runs:
        raise ValueError("run count does not match the declared expected count")
    if len({str(path.resolve()) for path in logs}) != len(logs):
        raise ValueError("run logs must be distinct")
    checked_hash(binary, binary_hash)
    checked_hash(config, config_hash)
    runs = [parse_run(path) for path in logs]
    attempts = {run["attempts"] for run in runs}
    if len(attempts) != 1:
        raise ValueError("mixed preparation counts across runs")
    walls = [run["total_wall_us"] for run in runs]
    cpus = [run["total_process_cpu_us"] for run in runs]
    return {
        "schema_version": 1,
        "scope": "binary_startup_observation_only",
        "binary_sha256": binary_hash,
        "config_sha256": config_hash,
        "run_count": len(runs),
        "run_log_sha256": [run["log_sha256"] for run in runs],
        "preparations_per_run": attempts.pop(),
        "wall_us": {
            "min": min(walls),
            "median": statistics.median(walls),
            "max": max(walls),
            "per_run": walls,
        },
        "process_cpu_us": None if any(value is None for value in cpus) else {
            "min": min(cpus),
            "median": statistics.median(cpus),
            "max": max(cpus),
            "per_run": cpus,
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--binary-sha256", required=True)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--config-sha256", required=True)
    parser.add_argument("--expected-runs", type=int, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("logs", nargs="+", type=Path)
    args = parser.parse_args()
    receipt = collect(args.binary, args.binary_sha256, args.config,
                      args.config_sha256, args.logs, args.expected_runs)
    with args.output.open("x", encoding="utf-8") as output:
        output.write(json.dumps(receipt, indent=2) + "\n")


if __name__ == "__main__":
    main()
