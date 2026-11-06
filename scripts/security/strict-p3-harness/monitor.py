#!/usr/bin/env python3
"""Strict, append-only exact-candidate P3 soak monitor.

This program runs on one fleet node.  It never changes the monitored services.
Every subprocess result is retained byte-for-byte (base64), including stderr,
return code, timeout state, and elapsed monotonic nanoseconds.
"""

from __future__ import annotations

import argparse
import base64
import datetime as dt
import fcntl
import hashlib
import json
import math
import os
import pathlib
import re
import stat
import subprocess
import tempfile
import time
import uuid
from typing import Any, Callable


SCHEMA = "aegis.strict-p3.node-attempt.v3"
ANCHOR_SCHEMA = "aegis.strict-p3.external-anchor.v1"


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def canonical(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def strict_json(raw: bytes) -> Any:
    def reject_constant(value: str) -> None:
        raise ValueError(f"non-finite JSON constant rejected: {value}")

    return json.loads(raw, parse_constant=reject_constant)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def write_exclusive(path: pathlib.Path, data: bytes, mode: int = 0o600) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        with os.fdopen(fd, "wb", closefd=False) as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        os.close(fd)


def read_regular_once(
    path: pathlib.Path,
    maximum_bytes: int = 16 * 1024 * 1024,
    require_private: bool = False,
) -> bytes:
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(path, flags)
    try:
        metadata = os.fstat(fd)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise RuntimeError(f"refusing non-regular or multiply-linked evidence: {path}")
        if require_private and metadata.st_mode & 0o077:
            raise RuntimeError(f"private file is group/world accessible: {path}")
        if metadata.st_size < 0 or metadata.st_size > maximum_bytes:
            raise RuntimeError(f"evidence size outside bound: {path}")
        chunks: list[bytes] = []
        remaining = maximum_bytes + 1
        while remaining > 0:
            chunk = os.read(fd, min(1024 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        if len(raw) > maximum_bytes or len(raw) != metadata.st_size:
            raise RuntimeError(f"evidence changed or exceeded bound while reading: {path}")
        return raw
    finally:
        os.close(fd)


def anchor_message(receipt_body: dict[str, Any]) -> bytes:
    return b"aegis.strict-p3.external-anchor.v1\x00" + canonical(receipt_body)


def key_bytes(path: pathlib.Path, private: bool) -> bytes:
    return read_regular_once(path, 16 * 1024, require_private=private)


def openssl_anchor_verify(public_key_raw: bytes, message: bytes, signature: bytes) -> bool:
    if len(signature) != 64:
        return False
    with tempfile.TemporaryDirectory(prefix="aegis-p3-verify-") as tmp:
        root = pathlib.Path(tmp)
        public_path = root / "public.pem"
        signature_path = root / "signature.bin"
        message_path = root / "message.bin"
        public_path.write_bytes(public_key_raw)
        signature_path.write_bytes(signature)
        message_path.write_bytes(message)
        try:
            proc = subprocess.run(
                [
                    "openssl", "pkeyutl", "-verify", "-rawin", "-pubin",
                    "-inkey", str(public_path), "-sigfile", str(signature_path),
                    "-in", str(message_path),
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
                timeout=30,
            )
        except (OSError, subprocess.TimeoutExpired):
            return False
    return proc.returncode == 0


def anchor_receipt_body(receipt: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in receipt.items() if key != "signature_b64"}


def verify_anchor_receipt(
    receipt: Any,
    entry: dict[str, Any],
    previous_receipt_sha256: str,
    trusted_public_key: bytes,
) -> list[str]:
    if not isinstance(receipt, dict):
        return ["anchor_not_object"]
    expected_fields = {
        "schema", "anchor_id", "attempt_id", "config_sha256", "sequence",
        "entry_sha256", "previous_receipt_sha256", "anchored_at_utc", "signature_b64",
    }
    failures: list[str] = []
    if set(receipt) != expected_fields:
        failures.append("anchor_fields")
    for key in ("attempt_id", "config_sha256", "sequence"):
        if receipt.get(key) != entry.get(key):
            failures.append(f"anchor_{key}")
    if receipt.get("schema") != ANCHOR_SCHEMA:
        failures.append("anchor_schema")
    if not isinstance(receipt.get("anchor_id"), str) or not receipt.get("anchor_id"):
        failures.append("anchor_id")
    if receipt.get("entry_sha256") != sha256(canonical(entry)):
        failures.append("anchor_entry_sha256")
    if receipt.get("previous_receipt_sha256") != previous_receipt_sha256:
        failures.append("anchor_previous_receipt")
    if not valid_utc(receipt.get("anchored_at_utc")):
        failures.append("anchor_time")
    try:
        signature = base64.b64decode(receipt.get("signature_b64", ""), validate=True)
    except (ValueError, TypeError):
        signature = b""
        failures.append("anchor_signature_encoding")
    if not openssl_anchor_verify(trusted_public_key, anchor_message(anchor_receipt_body(receipt)), signature):
        failures.append("anchor_signature")
    return sorted(set(failures))


def obtain_anchor_receipt(
    anchor_command: pathlib.Path,
    entry: dict[str, Any],
    previous_receipt_sha256: str,
    trusted_public_key: bytes,
) -> dict[str, Any]:
    if not anchor_command.is_absolute():
        raise ValueError("anchor command must be an absolute path")
    request = {
        "schema": ANCHOR_SCHEMA,
        "entry": entry,
        "previous_receipt_sha256": previous_receipt_sha256,
    }
    proc = subprocess.run(
        [str(anchor_command)],
        input=canonical(request),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=30,
    )
    if proc.returncode != 0 or proc.stderr or len(proc.stdout) > 16 * 1024:
        raise RuntimeError("external append-only anchor rejected the sample")
    try:
        receipt = strict_json(proc.stdout)
    except (ValueError, json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise RuntimeError("external anchor returned malformed receipt") from exc
    failures = verify_anchor_receipt(receipt, entry, previous_receipt_sha256, trusted_public_key)
    if failures:
        raise RuntimeError("external anchor receipt rejected: " + ",".join(failures))
    return receipt


def trusted_anchor_public_key(path: pathlib.Path, expected_sha256: str) -> bytes:
    if not re.fullmatch(r"[0-9a-f]{64}", expected_sha256):
        raise ValueError("trusted anchor public-key SHA-256 must be exact lowercase hex")
    raw = key_bytes(path, private=False)
    if sha256(raw) != expected_sha256:
        raise RuntimeError("trusted anchor public-key pin mismatch")
    return raw


def exact_bytes(value: bytes | str | None) -> bytes:
    if value is None:
        return b""
    return value if isinstance(value, bytes) else value.encode()


def run_probe(argv: list[str], timeout_seconds: float = 30.0) -> dict[str, Any]:
    started_utc = utc_now()
    started_ns = time.monotonic_ns()
    try:
        proc = subprocess.run(
            argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout_seconds,
            check=False,
        )
        stdout = proc.stdout
        stderr = proc.stderr
        returncode: int | None = proc.returncode
        timed_out = False
        exception = None
    except subprocess.TimeoutExpired as exc:
        stdout = exact_bytes(exc.stdout)
        stderr = exact_bytes(exc.stderr)
        returncode = None
        timed_out = True
        exception = "TimeoutExpired"
    elapsed_ns = time.monotonic_ns() - started_ns
    return {
        "argv": argv,
        "started_at_utc": started_utc,
        "elapsed_monotonic_ns": elapsed_ns,
        "timeout_seconds": timeout_seconds,
        "timed_out": timed_out,
        "returncode": returncode,
        "exception": exception,
        "stdout_b64": base64.b64encode(stdout).decode("ascii"),
        "stderr_b64": base64.b64encode(stderr).decode("ascii"),
        "stdout_sha256": sha256(stdout),
        "stderr_sha256": sha256(stderr),
        "stdout_bytes": len(stdout),
        "stderr_bytes": len(stderr),
    }


def output(probe: dict[str, Any]) -> bytes:
    return base64.b64decode(probe["stdout_b64"], validate=True)


def probe_ok(probe: dict[str, Any]) -> bool:
    return probe.get("returncode") == 0 and probe.get("timed_out") is False


def valid_utc(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    try:
        parsed = dt.datetime.fromisoformat(value)
    except ValueError:
        return False
    return parsed.tzinfo is not None and parsed.utcoffset() is not None


def probe_integrity_failures(probe: Any) -> list[str]:
    failures: list[str] = []
    if not isinstance(probe, dict):
        return ["not_object"]
    try:
        stdout = base64.b64decode(probe.get("stdout_b64", ""), validate=True)
        stderr = base64.b64decode(probe.get("stderr_b64", ""), validate=True)
    except (ValueError, TypeError):
        return ["invalid_base64"]
    if probe.get("stdout_sha256") != sha256(stdout) or probe.get("stdout_bytes") != len(stdout):
        failures.append("stdout_integrity")
    if probe.get("stderr_sha256") != sha256(stderr) or probe.get("stderr_bytes") != len(stderr):
        failures.append("stderr_integrity")
    if not isinstance(probe.get("argv"), list) or not all(isinstance(x, str) for x in probe["argv"]):
        failures.append("argv")
    if not valid_utc(probe.get("started_at_utc")):
        failures.append("started_at_utc")
    elapsed = probe.get("elapsed_monotonic_ns")
    if not isinstance(elapsed, int) or isinstance(elapsed, bool) or elapsed < 0:
        failures.append("elapsed_monotonic_ns")
    timeout = probe.get("timeout_seconds")
    if (
        not isinstance(timeout, (int, float))
        or isinstance(timeout, bool)
        or not math.isfinite(float(timeout))
        or timeout <= 0
    ):
        failures.append("timeout_seconds")
    timed_out = probe.get("timed_out")
    returncode = probe.get("returncode")
    if not isinstance(timed_out, bool):
        failures.append("timed_out")
    elif timed_out:
        if returncode is not None or probe.get("exception") != "TimeoutExpired":
            failures.append("timeout_result")
    elif not isinstance(returncode, int) or isinstance(returncode, bool) or probe.get("exception") is not None:
        failures.append("process_result")
    return failures


def parse_properties(probe: dict[str, Any]) -> dict[str, str]:
    if not probe_ok(probe):
        return {}
    try:
        text = output(probe).decode("utf-8", errors="strict")
        return dict(line.split("=", 1) for line in text.splitlines() if "=" in line)
    except (UnicodeDecodeError, ValueError):
        return {}


def nested(value: Any, dotted: str) -> Any:
    for part in dotted.split("."):
        if not isinstance(value, dict) or part not in value:
            return None
        value = value[part]
    return value


def valid_config(config: dict[str, Any]) -> None:
    candidate = config.get("candidate", {})
    if not re.fullmatch(r"[0-9a-f]{40}", candidate.get("source", "")):
        raise ValueError("candidate.source must be an exact 40-character lowercase Git SHA")
    if not re.fullmatch(r"[0-9a-f]{64}", candidate.get("binary_sha256", "")):
        raise ValueError("candidate.binary_sha256 must be an exact lowercase SHA-256")
    if not str(candidate.get("binary", "")).startswith("/"):
        raise ValueError("candidate.binary must be an absolute path")
    units = config.get("units")
    if not isinstance(units, list) or not units:
        raise ValueError("at least one unit is required")
    names = [row.get("name") for row in units]
    if len(names) != len(set(names)) or not all(isinstance(x, str) and x for x in names):
        raise ValueError("unit names must be unique non-empty strings")
    candidate_units = [row for row in units if row.get("candidate")]
    if len(candidate_units) != 1 or not candidate_units[0].get("immutable_pid"):
        raise ValueError("exactly one immutable candidate unit is required")
    for row in units:
        if not isinstance(row.get("immutable_pid"), bool):
            raise ValueError("every unit must explicitly declare immutable_pid")
        if not row["immutable_pid"] and not row.get("allow_zero_pid"):
            raise ValueError("non-immutable units must explicitly declare allow_zero_pid")
    thresholds = config.get("thresholds", {})
    duration = thresholds.get("minimum_duration_seconds", 0)
    samples = thresholds.get("minimum_samples", 0)
    maximum_gap_value = thresholds.get("maximum_gap_seconds", 0)
    for name, value in (
        ("minimum_duration_seconds", duration),
        ("minimum_samples", samples),
        ("maximum_gap_seconds", maximum_gap_value),
    ):
        if not isinstance(value, (int, float)) or isinstance(value, bool) or not math.isfinite(float(value)):
            raise ValueError(f"{name} must be finite")
    if float(duration) != int(duration) or int(duration) < 86400:
        raise ValueError("minimum_duration_seconds may not be below 86400")
    if float(samples) != int(samples) or int(samples) < 1400:
        raise ValueError("minimum_samples may not be below 1400")
    maximum_gap = float(maximum_gap_value)
    if maximum_gap <= 0 or maximum_gap > 180:
        raise ValueError("maximum_gap_seconds must be positive and may not exceed 180")
    listeners = config.get("listeners", [])
    if not {"tcp", "udp"}.issubset({row.get("protocol") for row in listeners}):
        raise ValueError("required process-owned TCP and UDP listeners may not be omitted")
    if not set(names).issubset(set(config.get("journal_units", []))):
        raise ValueError("journal_units must include every declared unit")
    semantic = config.get("semantic_probes", [])
    semantic_names = [row.get("name") for row in semantic]
    if not semantic or len(semantic_names) != len(set(semantic_names)) or not all(semantic_names):
        raise ValueError("at least one uniquely named semantic probe is required")
    for row in semantic:
        if not row.get("argv"):
            raise ValueError("each semantic probe requires argv")
        timeout = row.get("timeout_seconds", 30)
        if (
            not isinstance(timeout, (int, float))
            or isinstance(timeout, bool)
            or not math.isfinite(float(timeout))
            or float(timeout) <= 0
            or float(timeout) > 300
        ):
            raise ValueError("semantic timeout_seconds must be finite and in (0, 300]")
        assertions = 0
        if "json_equals" in row:
            value = row["json_equals"]
            if not isinstance(value, dict) or not value or not all(isinstance(key, str) and key for key in value):
                raise ValueError("semantic json_equals must be a non-empty object with non-empty paths")
            assertions += 1
        if "stdout_equals" in row:
            value = row["stdout_equals"]
            if not isinstance(value, str) or not value:
                raise ValueError("semantic stdout_equals must be a non-empty string")
            assertions += 1
        if "stdout_contains" in row:
            value = row["stdout_contains"]
            if not isinstance(value, list) or not value or not all(isinstance(item, str) and item for item in value):
                raise ValueError("semantic stdout_contains must contain non-empty strings")
            assertions += 1
        if assertions == 0:
            raise ValueError("each semantic probe requires a semantic output assertion")


def sample(config: dict[str, Any], runner: Callable[..., dict[str, Any]] = run_probe) -> dict[str, Any]:
    before_ns = time.clock_gettime_ns(time.CLOCK_BOOTTIME)
    probes: dict[str, dict[str, Any]] = {}
    probes["boot_id"] = runner(["cat", "/proc/sys/kernel/random/boot_id"])
    for unit in config["units"]:
        probes[f"unit:{unit['name']}"] = runner(
            [
                "systemctl", "show", unit["name"],
                "-p", "ActiveState", "-p", "MainPID", "-p", "NRestarts",
                "-p", "ActiveEnterTimestampMonotonic",
            ]
        )
    candidate_unit = next(row for row in config["units"] if row.get("candidate"))
    candidate_props = parse_properties(probes[f"unit:{candidate_unit['name']}"])
    pid = candidate_props.get("MainPID", "0")
    probes["candidate_executable"] = runner(["readlink", "-f", f"/proc/{pid}/exe"])
    probes["candidate_sha256"] = runner(["sha256sum", f"/proc/{pid}/exe"])
    probes["candidate_version"] = runner([config["candidate"]["binary"], "--version"])
    probes["listeners"] = runner(["ss", "-H", "-lntup"])
    for spec in config.get("semantic_probes", []):
        probes[f"semantic:{spec['name']}"] = runner(
            [str(x) for x in spec["argv"]], float(spec.get("timeout_seconds", 30))
        )
    after_ns = time.clock_gettime_ns(time.CLOCK_BOOTTIME)
    row: dict[str, Any] = {
        "schema": SCHEMA,
        "sample_id": str(uuid.uuid4()),
        "observed_at_utc": utc_now(),
        "boottime_before_ns": before_ns,
        "boottime_after_ns": after_ns,
        "probes": probes,
    }
    row["assessment"] = assess_sample(config, row)
    return row


def expected_probe_contract(config: dict[str, Any], row: dict[str, Any]) -> dict[str, tuple[list[str], float]]:
    contract: dict[str, tuple[list[str], float]] = {
        "boot_id": (["cat", "/proc/sys/kernel/random/boot_id"], 30.0),
        "candidate_version": ([config["candidate"]["binary"], "--version"], 30.0),
        "listeners": (["ss", "-H", "-lntup"], 30.0),
    }
    probes = row.get("probes", {}) if isinstance(row.get("probes"), dict) else {}
    for unit in config["units"]:
        name = unit["name"]
        contract[f"unit:{name}"] = ([
            "systemctl", "show", name,
            "-p", "ActiveState", "-p", "MainPID", "-p", "NRestarts",
            "-p", "ActiveEnterTimestampMonotonic",
        ], 30.0)
    candidate_unit = next(unit for unit in config["units"] if unit.get("candidate"))
    props = parse_properties(probes.get(f"unit:{candidate_unit['name']}", {}))
    pid = props.get("MainPID", "0")
    contract["candidate_executable"] = (["readlink", "-f", f"/proc/{pid}/exe"], 30.0)
    contract["candidate_sha256"] = (["sha256sum", f"/proc/{pid}/exe"], 30.0)
    for spec in config.get("semantic_probes", []):
        contract[f"semantic:{spec['name']}"] = (
            [str(value) for value in spec["argv"]],
            float(spec.get("timeout_seconds", 30)),
        )
    return contract


def sample_integrity_failures(config: dict[str, Any], row: Any, filename: str | None = None) -> list[str]:
    if not isinstance(row, dict):
        return ["not_object"]
    failures: list[str] = []
    if set(row) != {
        "schema", "sample_id", "observed_at_utc", "boottime_before_ns",
        "boottime_after_ns", "probes", "assessment",
    }:
        failures.append("fields")
    if row.get("schema") != SCHEMA:
        failures.append("schema")
    sample_id = row.get("sample_id")
    try:
        parsed_id = uuid.UUID(sample_id)
        if parsed_id.version != 4 or str(parsed_id) != sample_id:
            failures.append("sample_id")
    except (ValueError, TypeError, AttributeError):
        failures.append("sample_id")
    if not valid_utc(row.get("observed_at_utc")):
        failures.append("observed_at_utc")
    before = row.get("boottime_before_ns")
    after = row.get("boottime_after_ns")
    if (
        not isinstance(before, int) or isinstance(before, bool) or before < 0
        or not isinstance(after, int) or isinstance(after, bool) or after < before
    ):
        failures.append("boottime_interval")
    if filename is not None and isinstance(before, int) and isinstance(sample_id, str):
        if filename != f"{before:020d}-{sample_id}.json":
            failures.append("filename")
    probes = row.get("probes")
    contract = expected_probe_contract(config, row)
    if not isinstance(probes, dict) or set(probes) != set(contract):
        failures.append("probe_set")
        probes = probes if isinstance(probes, dict) else {}
    for name, (argv, timeout) in contract.items():
        probe = probes.get(name)
        for failure in probe_integrity_failures(probe):
            failures.append(f"probe:{name}:{failure}")
        if isinstance(probe, dict):
            if probe.get("argv") != argv:
                failures.append(f"probe:{name}:argv_contract")
            probe_timeout = probe.get("timeout_seconds")
            if not isinstance(probe_timeout, (int, float)) or float(probe_timeout) != timeout:
                failures.append(f"probe:{name}:timeout_contract")
    try:
        expected_assessment = assess_sample(config, row)
    except Exception:
        expected_assessment = None
        failures.append("assessment_unreadable")
    if row.get("assessment") != expected_assessment:
        failures.append("assessment_mismatch")
    return sorted(set(failures))


def listener_owned_by(lines: list[str], protocol: str, endpoint: str, pid: str) -> bool:
    if not pid.isdigit() or pid == "0":
        return False
    for line in lines:
        fields = line.split()
        if len(fields) < 6 or fields[0] != protocol or fields[4] != endpoint:
            continue
        if any(match.group(1) == pid for match in re.finditer(r"\bpid=(\d+)(?=[,)])", line)):
            return True
    return False


def assess_sample(config: dict[str, Any], row: dict[str, Any]) -> dict[str, Any]:
    failures: list[str] = []
    probes = row.get("probes", {})
    required_probe_names = ["boot_id", "candidate_executable", "candidate_sha256", "candidate_version", "listeners"]
    required_probe_names += [f"unit:{unit['name']}" for unit in config["units"]]
    required_probe_names += [f"semantic:{spec['name']}" for spec in config.get("semantic_probes", [])]
    for name in required_probe_names:
        if name not in probes or not probe_ok(probes[name]):
            failures.append(f"probe:{name}")
    unit_values: dict[str, dict[str, str]] = {}
    for unit in config["units"]:
        name = unit["name"]
        props = parse_properties(probes.get(f"unit:{name}", {}))
        unit_values[name] = props
        if props.get("ActiveState") != "active":
            failures.append(f"unit_active:{name}")
        if props.get("NRestarts") != "0":
            failures.append(f"unit_nrestarts:{name}")
        if unit.get("immutable_pid") and (not props.get("MainPID", "").isdigit() or props.get("MainPID") == "0"):
            failures.append(f"unit_pid:{name}")
    candidate = config["candidate"]
    try:
        executable = output(probes["candidate_executable"]).decode().strip()
        digest = output(probes["candidate_sha256"]).decode().split()[0]
        version = output(probes["candidate_version"]).decode()
    except (KeyError, UnicodeDecodeError, IndexError):
        executable = digest = version = ""
    if executable != candidate["binary"]:
        failures.append("candidate_path")
    if digest != candidate["binary_sha256"]:
        failures.append("candidate_sha256")
    if candidate["source"] not in version:
        failures.append("candidate_version_source")
    candidate_pid = unit_values.get(next(x["name"] for x in config["units"] if x.get("candidate")), {}).get("MainPID", "0")
    try:
        sockets = output(probes["listeners"]).decode("utf-8", errors="strict").splitlines()
    except (KeyError, UnicodeDecodeError):
        sockets = []
    for listener in config["listeners"]:
        proto = listener["protocol"]
        endpoint = f"{listener['address']}:{int(listener['port'])}"
        if not listener_owned_by(sockets, proto, endpoint, candidate_pid):
            failures.append(f"listener:{proto}:{endpoint}")
    for spec in config.get("semantic_probes", []):
        probe = probes.get(f"semantic:{spec['name']}", {})
        parsed: Any = None
        raw = b""
        if probe_ok(probe):
            raw = output(probe)
            try:
                parsed = json.loads(raw)
            except (json.JSONDecodeError, UnicodeDecodeError):
                if spec.get("json_equals"):
                    failures.append(f"semantic_json:{spec['name']}")
        for path, expected in spec.get("json_equals", {}).items():
            expected = candidate["source"] if expected == "$CANDIDATE_SOURCE" else expected
            if nested(parsed, path) != expected:
                failures.append(f"semantic_value:{spec['name']}:{path}")
        if "stdout_equals" in spec and raw != spec["stdout_equals"].encode():
            failures.append(f"semantic_stdout:{spec['name']}")
        for expected in spec.get("stdout_contains", []):
            if expected.encode() not in raw:
                failures.append(f"semantic_stdout_contains:{spec['name']}")
    boot_id = ""
    try:
        boot_id = output(probes["boot_id"]).decode().strip()
    except (KeyError, UnicodeDecodeError):
        pass
    try:
        parsed_boot_id = uuid.UUID(boot_id)
        boot_id_valid = str(parsed_boot_id) == boot_id
    except (ValueError, TypeError, AttributeError):
        boot_id_valid = False
    if not boot_id_valid:
        failures.append("boot_id")
    return {
        "status": "PASS" if not failures else "FAIL",
        "failures": sorted(set(failures)),
        "boot_id": boot_id,
        "units": unit_values,
    }


def capture_journal_cursors(config: dict[str, Any]) -> dict[str, Any]:
    return {
        unit: run_probe(["journalctl", "-u", unit, "-n", "0", "--show-cursor", "--no-pager"])
        for unit in config["journal_units"]
    }


def cursor_from(probe: dict[str, Any]) -> str | None:
    if not probe_ok(probe):
        return None
    match = re.search(rb"-- cursor: ([^\r\n]+)", output(probe))
    return match.group(1).decode("ascii", errors="strict") if match else None


def capture_journals(config: dict[str, Any], cursors: dict[str, Any]) -> dict[str, Any]:
    rows = {}
    for unit in config["journal_units"]:
        cursor = cursor_from(cursors.get(unit, {}))
        if cursor is None:
            rows[unit] = {"cursor_error": True, "probe": None}
        else:
            rows[unit] = {
                "cursor_error": False,
                "probe": run_probe([
                    "journalctl", "-u", unit, "--after-cursor", cursor,
                    "-p", "warning..emerg", "--no-pager", "--output=json",
                ], 60),
            }
    return rows


def evaluate(
    config: dict[str, Any],
    samples: list[dict[str, Any]],
    journals: dict[str, Any],
    sample_filenames: list[str] | None = None,
) -> dict[str, Any]:
    reasons: list[str] = []
    if not samples:
        return {"status": "FAIL", "reasons": ["no_samples"]}
    if sample_filenames is not None and len(sample_filenames) != len(samples):
        reasons.append("sample_filename_count")
    evidence_failures: dict[str, list[str]] = {}
    assessed: list[dict[str, Any]] = []
    for index, row in enumerate(samples):
        filename = sample_filenames[index] if sample_filenames is not None and index < len(sample_filenames) else None
        failures = sample_integrity_failures(config, row, filename)
        if failures:
            evidence_failures[filename or f"index:{index}"] = failures
            reasons.append("invalid_sample_evidence")
        if isinstance(row, dict):
            checked = dict(row)
            try:
                checked["assessment"] = assess_sample(config, row)
            except Exception:
                checked["assessment"] = {
                    "status": "FAIL",
                    "failures": ["sample_evidence_unreadable"],
                    "boot_id": "",
                    "units": {},
                }
            assessed.append(checked)
    if not assessed:
        return {
            "status": "FAIL",
            "reasons": sorted(set(reasons) | {"no_valid_sample_objects"}),
            "sample_evidence_failures": evidence_failures,
        }
    ordered = sorted(
        assessed,
        key=lambda row: row.get("boottime_before_ns")
        if isinstance(row.get("boottime_before_ns"), int) and not isinstance(row.get("boottime_before_ns"), bool)
        else -1,
    )
    if [row.get("sample_id") for row in assessed] != [row.get("sample_id") for row in ordered]:
        reasons.append("sample_sequence_out_of_order")
    first, last = ordered[0], ordered[-1]
    thresholds = config["thresholds"]
    # Count only the fully observed interval. Probe execution at either edge
    # cannot be borrowed to reach the 24-hour threshold.
    number = lambda value: value if isinstance(value, int) and not isinstance(value, bool) else 0
    duration_ns = number(last.get("boottime_before_ns")) - number(first.get("boottime_after_ns"))
    gaps_ns = [
        number(b.get("boottime_before_ns")) - number(a.get("boottime_after_ns"))
        for a, b in zip(ordered, ordered[1:])
    ]
    if any(gap < 0 for gap in gaps_ns):
        reasons.append("overlapping_or_reversed_samples")
    if duration_ns < int(thresholds["minimum_duration_seconds"]) * 1_000_000_000:
        reasons.append("minimum_duration")
    if len(ordered) < int(thresholds["minimum_samples"]):
        reasons.append("minimum_samples")
    max_gap_ns = max(gaps_ns, default=0)
    if max_gap_ns > float(thresholds["maximum_gap_seconds"]) * 1_000_000_000:
        reasons.append("maximum_gap")
    if any(row.get("assessment", {}).get("status") != "PASS" for row in ordered):
        reasons.append("failed_sample")
    sample_ids = [row.get("sample_id") for row in ordered]
    if not all(isinstance(value, str) for value in sample_ids) or len(sample_ids) != len(set(sample_ids)):
        reasons.append("duplicate_sample_id")
    intervals = [(row.get("boottime_before_ns"), row.get("boottime_after_ns")) for row in ordered]
    if not all(isinstance(before, int) and isinstance(after, int) for before, after in intervals) or len(intervals) != len(set(intervals)):
        reasons.append("duplicate_sample_interval")
    boot_ids = {row.get("assessment", {}).get("boot_id") for row in ordered}
    if len(boot_ids) != 1 or "" in boot_ids or None in boot_ids:
        reasons.append("boot_changed_or_unknown")
    baseline_units = first.get("assessment", {}).get("units", {})
    for unit in config["units"]:
        if not unit.get("immutable_pid"):
            continue
        name = unit["name"]
        initial = baseline_units.get(name, {}).get("MainPID")
        if not initial or any(row.get("assessment", {}).get("units", {}).get(name, {}).get("MainPID") != initial for row in ordered):
            reasons.append(f"pid_changed:{name}")
    journal_counts: dict[str, int | None] = {}
    for unit in config["journal_units"]:
        entry = journals.get(unit, {})
        probe = entry.get("probe")
        if entry.get("cursor_error") or not isinstance(probe, dict) or not probe_ok(probe):
            reasons.append(f"journal_probe:{unit}")
            journal_counts[unit] = None
            continue
        lines = [line for line in output(probe).splitlines() if line.strip()]
        journal_counts[unit] = len(lines)
        if lines:
            reasons.append(f"journal_entries:{unit}")
    return {
        "status": "PASS" if not reasons else "FAIL",
        "reasons": sorted(set(reasons)),
        "duration_seconds": duration_ns / 1_000_000_000,
        "sample_count": len(ordered),
        "failed_sample_count": sum(row.get("assessment", {}).get("status") != "PASS" for row in ordered),
        "maximum_gap_seconds": max_gap_ns / 1_000_000_000,
        "journal_warning_error_counts": journal_counts,
        "first_sample_id": first.get("sample_id"),
        "last_sample_id": last.get("sample_id"),
        "sample_evidence_failures": evidence_failures,
    }


def load_json(path: pathlib.Path) -> Any:
    return strict_json(read_regular_once(path))


def load_attempt_config(root: pathlib.Path) -> tuple[dict[str, Any], dict[str, Any]]:
    attempt = load_json(root / "attempt.json")
    config = load_json(root / "config.json")
    valid_config(config)
    if sha256(canonical(config)) != attempt.get("config_sha256"):
        raise RuntimeError("attempt config changed after initialization")
    return attempt, config


def locked(root: pathlib.Path):
    stream = (root / ".lock").open("a+b")
    fcntl.flock(stream.fileno(), fcntl.LOCK_EX)
    return stream


def store_sample(root: pathlib.Path, row: dict[str, Any]) -> pathlib.Path:
    path = root / "samples" / f"{row['boottime_before_ns']:020d}-{row['sample_id']}.json"
    write_exclusive(path, canonical(row))
    return path


def read_sample_chain(root: pathlib.Path) -> tuple[list[dict[str, Any]], list[str], bytes]:
    path = root / "sample-chain.jsonl"
    try:
        chain_raw = read_regular_once(path)
    except (FileNotFoundError, OSError, RuntimeError):
        return [], ["sample_chain_missing_or_unsafe"], b""
    entries: list[dict[str, Any]] = []
    failures: list[str] = []
    previous_hash = "0" * 64
    seen_files: set[str] = set()
    for index, raw in enumerate(chain_raw.splitlines(keepends=True)):
        try:
            entry = strict_json(raw)
        except (json.JSONDecodeError, UnicodeDecodeError):
            failures.append(f"sample_chain_malformed:{index}")
            continue
        if not isinstance(entry, dict) or set(entry) != {
            "attempt_id", "config_sha256", "sequence", "sample",
            "sample_sha256", "previous_entry_sha256",
        }:
            failures.append(f"sample_chain_fields:{index}")
            continue
        if raw != canonical(entry):
            failures.append(f"sample_chain_noncanonical:{index}")
        sample_name = entry.get("sample")
        if entry.get("sequence") != index:
            failures.append(f"sample_chain_sequence:{index}")
        if entry.get("previous_entry_sha256") != previous_hash:
            failures.append(f"sample_chain_previous:{index}")
        if (
            not isinstance(sample_name, str)
            or pathlib.PurePath(sample_name).name != sample_name
            or not sample_name.endswith(".json")
            or sample_name in seen_files
        ):
            failures.append(f"sample_chain_sample:{index}")
        if not re.fullmatch(r"[0-9a-f]{64}", str(entry.get("sample_sha256", ""))):
            failures.append(f"sample_chain_digest:{index}")
        if isinstance(sample_name, str):
            seen_files.add(sample_name)
        entries.append(entry)
        previous_hash = sha256(canonical(entry))
    if not entries:
        failures.append("sample_chain_empty")
    return entries, sorted(set(failures)), chain_raw


def append_sample_chain(
    root: pathlib.Path,
    sample_path: pathlib.Path,
    attempt_id: str,
    config_sha256: str,
    anchor_command: pathlib.Path,
    trusted_public_key: bytes,
) -> str:
    chain_path = root / "sample-chain.jsonl"
    if chain_path.exists():
        entries, failures, _ = read_sample_chain(root)
        if failures:
            raise RuntimeError("sample chain is invalid: " + ",".join(failures))
        previous_hash = sha256(canonical(entries[-1]))
        sequence = len(entries)
        previous_anchor_path = root / "anchors" / f"{entries[-1]['sample']}.anchor.json"
        previous_receipt_sha256 = sha256(read_regular_once(previous_anchor_path, 16 * 1024))
    else:
        previous_hash = "0" * 64
        previous_receipt_sha256 = "0" * 64
        sequence = 0
    entry = {
        "attempt_id": attempt_id,
        "config_sha256": config_sha256,
        "sequence": sequence,
        "sample": sample_path.name,
        "sample_sha256": sha256(read_regular_once(sample_path)),
        "previous_entry_sha256": previous_hash,
    }
    encoded = canonical(entry)
    receipt = obtain_anchor_receipt(
        anchor_command, entry, previous_receipt_sha256, trusted_public_key,
    )
    receipt_path = root / "anchors" / f"{sample_path.name}.anchor.json"
    write_exclusive(receipt_path, canonical(receipt))
    if sequence == 0:
        write_exclusive(chain_path, encoded)
    else:
        flags = os.O_WRONLY | os.O_APPEND
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        fd = os.open(chain_path, flags)
        try:
            with os.fdopen(fd, "ab", closefd=False) as stream:
                stream.write(encoded)
                stream.flush()
                os.fsync(stream.fileno())
        finally:
            os.close(fd)
    return sha256(encoded)


def verify_sample_chain(
    root: pathlib.Path,
    attempt_id: str,
    config_sha256: str,
    trusted_public_key: bytes,
) -> tuple[
    list[tuple[pathlib.Path, bytes]],
    list[str],
    list[dict[str, Any]],
    bytes,
    list[dt.datetime],
    dict[pathlib.Path, bytes],
]:
    entries, failures, chain_raw = read_sample_chain(root)
    samples: list[tuple[pathlib.Path, bytes]] = []
    declared_anchors: set[str] = set()
    previous_receipt_sha256 = "0" * 64
    anchor_id: str | None = None
    anchor_times: list[dt.datetime] = []
    anchor_raw: dict[pathlib.Path, bytes] = {}
    for index, entry in enumerate(entries):
        if entry.get("attempt_id") != attempt_id:
            failures.append(f"sample_chain_attempt:{index}")
        if entry.get("config_sha256") != config_sha256:
            failures.append(f"sample_chain_config:{index}")
        name = entry.get("sample")
        if not isinstance(name, str) or pathlib.PurePath(name).name != name:
            continue
        path = root / "samples" / name
        try:
            raw = read_regular_once(path)
            samples.append((path, raw))
        except (FileNotFoundError, OSError, RuntimeError):
            failures.append(f"sample_chain_missing_file:{index}")
            continue
        if sha256(raw) != entry.get("sample_sha256"):
            failures.append(f"sample_chain_file_digest:{index}")
        anchor_name = f"{name}.anchor.json"
        declared_anchors.add(anchor_name)
        anchor_path = root / "anchors" / anchor_name
        try:
            receipt_raw = read_regular_once(anchor_path, 16 * 1024)
            receipt = strict_json(receipt_raw)
        except (FileNotFoundError, OSError, RuntimeError):
            failures.append(f"sample_chain_anchor_file:{index}")
            continue
        except (ValueError, json.JSONDecodeError, UnicodeDecodeError):
            failures.append(f"sample_chain_anchor_malformed:{index}")
            continue
        if receipt_raw != canonical(receipt):
            failures.append(f"sample_chain_anchor_noncanonical:{index}")
        anchor_raw[anchor_path] = receipt_raw
        for failure in verify_anchor_receipt(receipt, entry, previous_receipt_sha256, trusted_public_key):
            failures.append(f"sample_chain_{failure}:{index}")
        current_anchor_id = receipt.get("anchor_id") if isinstance(receipt, dict) else None
        if anchor_id is None:
            anchor_id = current_anchor_id
        elif current_anchor_id != anchor_id:
            failures.append(f"sample_chain_anchor_id_changed:{index}")
        try:
            anchor_times.append(dt.datetime.fromisoformat(receipt["anchored_at_utc"]))
        except (KeyError, TypeError, ValueError):
            pass
        previous_receipt_sha256 = sha256(receipt_raw)
    actual = {path.name for path in (root / "samples").glob("*.json")}
    declared = {path.name for path, _ in samples}
    if actual != declared:
        failures.append("sample_chain_file_set")
    actual_anchors = {path.name for path in (root / "anchors").glob("*.anchor.json")}
    if actual_anchors != declared_anchors:
        failures.append("sample_chain_anchor_set")
    if len(anchor_times) != len(entries) or any(
        later <= earlier for earlier, later in zip(anchor_times, anchor_times[1:])
    ):
        failures.append("sample_chain_anchor_time_order")
    return samples, sorted(set(failures)), entries, chain_raw, anchor_times, anchor_raw


def initialize(
    config_path: pathlib.Path,
    attempt_dir: pathlib.Path,
    anchor_command: pathlib.Path,
    trusted_public_key_path: pathlib.Path,
    trusted_public_key_sha256: str,
) -> None:
    config_raw = read_regular_once(config_path)
    config = strict_json(config_raw)
    valid_config(config)
    attempt_id = attempt_dir.name
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", attempt_id):
        raise ValueError("attempt directory basename must be a bounded safe identifier")
    trusted_public_key = trusted_anchor_public_key(trusted_public_key_path, trusted_public_key_sha256)
    config_sha256 = sha256(canonical(config))
    attempt_dir.mkdir(mode=0o700, parents=True, exist_ok=False)
    (attempt_dir / "samples").mkdir(mode=0o700)
    (attempt_dir / "anchors").mkdir(mode=0o700)
    write_exclusive(attempt_dir / "config.json", canonical(config))
    cursors = capture_journal_cursors(config)
    write_exclusive(attempt_dir / "journal-cursors.json", canonical(cursors))
    row = sample(config)
    sample_path = store_sample(attempt_dir, row)
    chain_start_sha256 = append_sample_chain(
        attempt_dir, sample_path, attempt_id, config_sha256, anchor_command, trusted_public_key,
    )
    cursors_ok = all(probe_ok(value) and cursor_from(value) is not None for value in cursors.values())
    baseline_ok = row["assessment"]["status"] == "PASS" and cursors_ok
    attempt = {
        "schema": SCHEMA,
        "status": "RUNNING" if baseline_ok else "FAILED_BASELINE_RETAINED",
        "initialized_at_utc": utc_now(),
        "attempt_id": attempt_id,
        "config_sha256": config_sha256,
        "anchor_public_key_sha256": trusted_public_key_sha256,
        "baseline_sample": sample_path.name,
        "baseline_sample_sha256": sha256(read_regular_once(sample_path)),
        "sample_chain_start_sha256": chain_start_sha256,
        "journal_cursors_sha256": sha256(read_regular_once(attempt_dir / "journal-cursors.json")),
    }
    write_exclusive(attempt_dir / "attempt.json", canonical(attempt))
    print(json.dumps(attempt, sort_keys=True))
    if not baseline_ok:
        raise SystemExit(1)


def append_sample(
    attempt_dir: pathlib.Path,
    anchor_command: pathlib.Path,
    trusted_public_key_path: pathlib.Path,
    trusted_public_key_sha256: str,
) -> None:
    with locked(attempt_dir):
        if (attempt_dir / "final.json").exists():
            raise SystemExit("attempt is already finalized")
        attempt, config = load_attempt_config(attempt_dir)
        trusted_public_key = trusted_anchor_public_key(trusted_public_key_path, trusted_public_key_sha256)
        if attempt.get("anchor_public_key_sha256") != trusted_public_key_sha256:
            raise RuntimeError("anchor public-key pin changed after initialization")
        row = sample(config)
        path = store_sample(attempt_dir, row)
        append_sample_chain(
            attempt_dir, path, attempt["attempt_id"], attempt["config_sha256"],
            anchor_command, trusted_public_key,
        )
    print(json.dumps({"status": row["assessment"]["status"], "sample": path.name}))
    if row["assessment"]["status"] != "PASS":
        raise SystemExit(1)


def finalize(
    attempt_dir: pathlib.Path,
    anchor_command: pathlib.Path,
    trusted_public_key_path: pathlib.Path,
    trusted_public_key_sha256: str,
) -> None:
    with locked(attempt_dir):
        final_path = attempt_dir / "final.json"
        if final_path.exists():
            raise SystemExit("refusing to overwrite final.json")
        attempt, config = load_attempt_config(attempt_dir)
        attempt_raw = read_regular_once(attempt_dir / "attempt.json")
        config_raw = read_regular_once(attempt_dir / "config.json")
        if strict_json(attempt_raw) != attempt or strict_json(config_raw) != config:
            raise RuntimeError("attempt or config changed while finalization started")
        trusted_public_key = trusted_anchor_public_key(trusted_public_key_path, trusted_public_key_sha256)
        if attempt.get("anchor_public_key_sha256") != trusted_public_key_sha256:
            raise RuntimeError("anchor public-key pin changed after initialization")
        row = sample(config)
        final_sample_path = store_sample(attempt_dir, row)
        append_sample_chain(
            attempt_dir, final_sample_path, attempt["attempt_id"], attempt["config_sha256"],
            anchor_command, trusted_public_key,
        )
        cursors_path = attempt_dir / "journal-cursors.json"
        cursors_raw = read_regular_once(cursors_path)
        cursors = strict_json(cursors_raw)
        integrity_failures = []
        if sha256(cursors_raw) != attempt.get("journal_cursors_sha256"):
            integrity_failures.append("journal_cursors_changed")
        baseline_path = attempt_dir / "samples" / str(attempt.get("baseline_sample", ""))
        try:
            baseline_raw = read_regular_once(baseline_path)
        except (FileNotFoundError, OSError, RuntimeError):
            baseline_raw = b""
        if sha256(baseline_raw) != attempt.get("baseline_sample_sha256"):
            integrity_failures.append("baseline_sample_changed")
        chain_samples, chain_failures, chain_entries, chain_raw, anchor_times, anchor_raw = verify_sample_chain(
            attempt_dir, attempt["attempt_id"], attempt["config_sha256"], trusted_public_key,
        )
        integrity_failures.extend(chain_failures)
        if not chain_entries or sha256(canonical(chain_entries[0])) != attempt.get("sample_chain_start_sha256"):
            integrity_failures.append("sample_chain_start_changed")
        if chain_samples and chain_samples[0][0].name != attempt.get("baseline_sample"):
            integrity_failures.append("sample_chain_baseline_mismatch")
        journals = capture_journals(config, cursors)
        journal_name = f"journals-{row['sample_id']}.json"
        journal_path = attempt_dir / journal_name
        write_exclusive(journal_path, canonical(journals))
        journal_raw = read_regular_once(journal_path)
        malformed: list[str] = []
        samples = []
        sample_names = []
        sample_raw: dict[pathlib.Path, bytes] = {}
        for path, raw in chain_samples:
            try:
                samples.append(strict_json(raw))
                sample_names.append(path.name)
                sample_raw[path] = raw
            except Exception:
                malformed.append(path.name)
        result = evaluate(config, samples, journals, sample_names)
        if anchor_times:
            anchor_duration = (anchor_times[-1] - anchor_times[0]).total_seconds()
            anchor_gaps = [
                (later - earlier).total_seconds()
                for earlier, later in zip(anchor_times, anchor_times[1:])
            ]
            result["anchor_duration_seconds"] = anchor_duration
            result["anchor_maximum_gap_seconds"] = max(anchor_gaps, default=0)
            if anchor_duration < int(config["thresholds"]["minimum_duration_seconds"]):
                result["status"] = "FAIL"
                result["reasons"] = sorted(set(result.get("reasons", [])) | {"anchor_minimum_duration"})
            if max(anchor_gaps, default=0) > float(config["thresholds"]["maximum_gap_seconds"]):
                result["status"] = "FAIL"
                result["reasons"] = sorted(set(result.get("reasons", [])) | {"anchor_maximum_gap"})
        else:
            result["status"] = "FAIL"
            result["reasons"] = sorted(set(result.get("reasons", [])) | {"anchor_times_missing"})
        if malformed:
            result["status"] = "FAIL"
            result["reasons"] = sorted(set(result.get("reasons", [])) | {"malformed_sample_evidence"})
        if integrity_failures:
            result["status"] = "FAIL"
            result["reasons"] = sorted(set(result.get("reasons", [])) | set(integrity_failures))
        evidence_bytes = [
            (attempt_dir / "attempt.json", attempt_raw),
            (attempt_dir / "config.json", config_raw),
            (attempt_dir / "journal-cursors.json", cursors_raw),
            (journal_path, journal_raw),
        ]
        evidence_bytes.append((attempt_dir / "sample-chain.jsonl", chain_raw))
        evidence_bytes.extend(sorted(sample_raw.items(), key=lambda item: item[0].name))
        evidence_bytes.extend(sorted(anchor_raw.items(), key=lambda item: item[0].name))
        result.update({
            "schema": SCHEMA,
            "finalized_at_utc": utc_now(),
            "attempt_id": attempt_dir.name,
            "candidate": config["candidate"],
            "anchor_public_key_sha256": trusted_public_key_sha256,
            "malformed_sample_files": malformed,
            "journals_file": journal_name,
            "evidence_manifest": [
                {
                    "path": str(path.relative_to(attempt_dir)),
                    "sha256": sha256(raw),
                    "bytes": len(raw),
                }
                for path, raw in evidence_bytes
            ],
            "beta_exit": False,
        })
        write_exclusive(final_path, canonical(result))
    print(json.dumps(result, sort_keys=True))
    if result["status"] != "PASS":
        raise SystemExit(1)


def main() -> None:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    init = sub.add_parser("init")
    init.add_argument("--config", required=True, type=pathlib.Path)
    init.add_argument("--attempt-dir", required=True, type=pathlib.Path)
    for name in ("sample", "finalize"):
        child = sub.add_parser(name)
        child.add_argument("--attempt-dir", required=True, type=pathlib.Path)
    for child in (init, *[sub.choices[name] for name in ("sample", "finalize")]):
        child.add_argument("--anchor-command", required=True, type=pathlib.Path)
        child.add_argument("--trusted-anchor-public-key", required=True, type=pathlib.Path)
        child.add_argument("--trusted-anchor-public-key-sha256", required=True)
    args = parser.parse_args()
    if args.command == "init":
        initialize(
            args.config, args.attempt_dir, args.anchor_command,
            args.trusted_anchor_public_key, args.trusted_anchor_public_key_sha256,
        )
    elif args.command == "sample":
        append_sample(
            args.attempt_dir, args.anchor_command,
            args.trusted_anchor_public_key, args.trusted_anchor_public_key_sha256,
        )
    else:
        finalize(
            args.attempt_dir, args.anchor_command,
            args.trusted_anchor_public_key, args.trusted_anchor_public_key_sha256,
        )


if __name__ == "__main__":
    main()
