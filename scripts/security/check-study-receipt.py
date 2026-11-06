#!/usr/bin/env python3
"""Offline, redacted receipt validation; no execution or privacy acceptance."""
import datetime
import json
import os
from pathlib import Path
import re
import stat
import sys

SCHEMA_PATH = Path(__file__).resolve().parents[2] / "docs/grants/study-receipt.schema.json"
MAX_BYTES = 10 * 1024 * 1024
MAX_MS = 120000
FIELDS = {
    "schema_version", "attempt_id", "release_sha256", "profile_class",
    "environment_class", "network_cohort", "confirmed_ready_at", "started_at",
    "ended_at", "capture_confirmed_ready_at", "capture_started_at",
    "capture_ended_at", "independent_witness", "attempts",
    "authenticated_sessions", "delivered_bytes", "traffic_bytes_total", "elapsed_ms", "termination",
    "rollback", "publication_approval",
}
ENUMS = {
    "profile_class": {"baseline", "candidate", "socks-only", "full-wide-tun", "enrolled", "https-bridge"},
    "environment_class": {"controlled-lab", "consented-field"},
    "network_cohort": {"withheld", "controlled", "consented-cohort"},
    "independent_witness": {"absent", "approved-study-role"},
    "termination": {"not-run", "refused", "stopped", "failed", "completed"},
    "rollback": {"not-run", "restored", "failed"},
}
TIMES = ("confirmed_ready_at", "started_at", "ended_at", "capture_confirmed_ready_at", "capture_started_at", "capture_ended_at")
STAMP = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,3})?(?:Z|\+00:00)\Z")


def _result(valid, code, status="invalid", capture="absent", capture_ms=None):
    return {"valid": valid, "code": code, "status": status,
            "capture_evidence": capture, "capture_elapsed_ms": capture_ms,
            "privacy_acceptance": "not-established", "acceptance_established": False}


def validate_receipt(value):
    """Return fixed codes and aggregate status only; never input data or paths."""
    if not isinstance(value, dict) or set(value) != FIELDS:
        return _result(False, "shape")
    if type(value["schema_version"]) is not int or value["schema_version"] != 1:
        return _result(False, "version")
    if not isinstance(value["attempt_id"], str) or re.fullmatch(r"study-[0-9a-f]{32}", value["attempt_id"]) is None:
        return _result(False, "identifier")
    if not isinstance(value["release_sha256"], str) or re.fullmatch(r"[0-9a-f]{64}", value["release_sha256"]) is None:
        return _result(False, "digest")
    for field, allowed in ENUMS.items():
        if not isinstance(value[field], str) or value[field] not in allowed:
            return _result(False, "label")
    if type(value["publication_approval"]) is not bool:
        return _result(False, "approval")
    for field, maximum in (("attempts", 2), ("authenticated_sessions", 2), ("delivered_bytes", MAX_BYTES), ("traffic_bytes_total", MAX_BYTES), ("elapsed_ms", MAX_MS)):
        if type(value[field]) is not int or not 0 <= value[field] <= maximum:
            return _result(False, "counter")
    if value["authenticated_sessions"] > value["attempts"] or value["delivered_bytes"] > value["traffic_bytes_total"] or (value["delivered_bytes"] and not value["authenticated_sessions"]):
        return _result(False, "counter-order")
    times = {}
    for field in TIMES:
        stamp = value[field]
        if stamp is None:
            times[field] = None
            continue
        if not isinstance(stamp, str) or STAMP.fullmatch(stamp) is None:
            return _result(False, "timestamp")
        try:
            times[field] = datetime.datetime.fromisoformat(stamp.replace("Z", "+00:00"))
        except ValueError:
            return _result(False, "timestamp")
    start, end = times["started_at"], times["ended_at"]
    capture_start, capture_end = times["capture_started_at"], times["capture_ended_at"]
    if (start is None) != (end is None) or (capture_start is None) != (capture_end is None):
        return _result(False, "time-pair")
    status = value["termination"]
    counters = (value["attempts"], value["authenticated_sessions"], value["delivered_bytes"], value["traffic_bytes_total"], value["elapsed_ms"])
    if start is None:
        if any(counters) or capture_start is not None or times["capture_confirmed_ready_at"] is not None or value["rollback"] != "not-run" or status not in {"not-run", "refused", "failed"}:
            return _result(False, "no-run")
        if value["independent_witness"] != "absent":
            return _result(False, "no-run-witness")
        return _result(True, "valid", status)
    if status not in {"completed", "failed", "stopped"} or not value["attempts"]:
        return _result(False, "run-status")
    if times["confirmed_ready_at"] is None or times["confirmed_ready_at"] > start:
        return _result(False, "readiness")
    delta = end - start
    duration = (delta.days * 86400 + delta.seconds) * 1000 + delta.microseconds // 1000
    if not 0 < duration <= MAX_MS or duration != value["elapsed_ms"]:
        return _result(False, "run-duration")
    if value["rollback"] == "not-run":
        return _result(False, "rollback")
    if status == "completed" and (not value["authenticated_sessions"] or value["rollback"] != "restored"):
        return _result(False, "completion")
    if capture_start is None:
        if times["capture_confirmed_ready_at"] is not None:
            return _result(False, "capture-readiness-without-capture")
        return _result(True, "valid", status)
    confirmed = times["capture_confirmed_ready_at"]
    if confirmed is None or confirmed >= capture_start:
        return _result(False, "capture-readiness")
    delta = capture_end - capture_start
    capture_ms = (delta.days * 86400 + delta.seconds) * 1000 + delta.microseconds // 1000
    if not 0 < capture_ms <= MAX_MS:
        return _result(False, "capture-duration")
    evidence = "partial"
    if capture_start <= start and capture_end >= end and value["independent_witness"] != "absent":
        evidence = "full-interval-with-witness"
    return _result(True, "valid", status, evidence, int(capture_ms))


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate")
        result[key] = value
    return result


def main(argv=None):
    args = sys.argv[1:] if argv is None else argv
    if len(args) != 1 or not args[0] or args[0].startswith("-"):
        result = _result(False, "input")
    else:
        try:
            fd = os.open(args[0], os.O_RDONLY | os.O_NONBLOCK | getattr(os, "O_NOFOLLOW", 0))
            with os.fdopen(fd, "rb") as stream:
                info = os.fstat(stream.fileno())
                if not stat.S_ISREG(info.st_mode) or info.st_size > 65536:
                    raise ValueError("input")
                raw = stream.read(65537)
                if len(raw) > 65536:
                    raise ValueError("input")
            value = json.loads(raw, object_pairs_hook=_unique_object, parse_constant=lambda _: (_ for _ in ()).throw(ValueError("number")))
            result = validate_receipt(value)
        except (OSError, ValueError, TypeError, RecursionError, OverflowError):
            result = _result(False, "input")
    print(json.dumps(result, sort_keys=True))
    return 0 if result["valid"] else 1


if __name__ == "__main__":
    sys.exit(main())
