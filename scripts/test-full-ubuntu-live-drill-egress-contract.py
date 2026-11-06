#!/usr/bin/env python3
"""QA only: actual admission prefix and the two original verdict arms.

The optional pinned baseline selects historical legitimate positive references
only in paired QA. Current-source CI uses an independent TEST-NET reference.
No native lane, capture or network executes.
An independent outer owned-process supervisor is required for the whole fixture.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import signal
import struct
import subprocess
import sys
import tempfile
import time

BASELINE_SHA = "a605ff81339a6206aaa3b28d81e7c9efb7deebe642f5dd6831849b4c13eedc7f"
REFUSAL = b"FATAL: explicit canonical IPv4 EXPECTED_EGRESS_IPS allow-set required\n"
MARKER = b"# ---- pre-flight ----\n"


def digest(data):
    return hashlib.sha256(data).hexdigest()


def private_write(path, data, executable=False):
    with path.open("xb") as out:
        out.write(data)
    path.chmod(0o700 if executable else 0o600)


def actual_arm(source, lane):
    anchor = ("record_verdict " + lane + " PASS ").encode()
    if source.count(anchor) != 1:
        raise ValueError("actual_arm_anchor")
    offset = source.index(anchor)
    start = source.rfind(b"\n    if ", 0, offset) + 1
    finish = source.index(b"\n    fi\n", offset) + len(b"\n    fi\n")
    arm = source[start:finish]
    if not arm.startswith(b"    if ") or arm.count(anchor) != 1:
        raise ValueError("actual_arm_boundary")
    return arm


def run_owned(argv, env, directory):
    started = time.monotonic()
    process = subprocess.Popen(argv, env=env, cwd=directory,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    timed_out = False
    reaped_and_terminal = False
    cleanup_error = None
    try:
        stdout, stderr = process.communicate(timeout=10)
        reaped_and_terminal = process.returncode is not None
    except subprocess.TimeoutExpired:
        timed_out = True
        # This direct child remains owned by Popen. Do not signal a numeric
        # group or claim descendant quiescence from this local observation.
        try:
            process.kill()
        except ProcessLookupError:
            pass
        except OSError as error:
            cleanup_error = type(error).__name__
        try:
            stdout, stderr = process.communicate(timeout=4)
            reaped_and_terminal = process.returncode is not None
        except subprocess.TimeoutExpired:
            stdout, stderr = b"", b""
            cleanup_error = "TimeoutExpired"
    private_write(directory / "stdout.log", stdout)
    private_write(directory / "stderr.log", stderr)
    return {"exit_code": process.returncode, "pid": process.pid,
            "elapsed_seconds": time.monotonic() - started,
            "timed_out": timed_out,
            "direct_parent_reaped_and_pipes_terminal": reaped_and_terminal,
            "cleanup_error_type": cleanup_error,
            "stdout_sha256": digest(stdout), "stderr_sha256": digest(stderr)}, stdout, stderr


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--script", type=Path, required=True)
    parser.add_argument("--baseline-source", type=Path)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--bash", required=True)
    args = parser.parse_args()
    source = args.script.resolve(strict=True).read_bytes()
    baseline = None
    if args.baseline_source is not None:
        baseline = args.baseline_source.resolve(strict=True).read_bytes()
        if digest(baseline) != BASELINE_SHA:
            raise ValueError("pinned_original_reference")
    if source.count(MARKER) != 1:
        raise ValueError("current_boundary")
    prefix = source[:source.index(MARKER)]
    arms = {lane: actual_arm(source, lane) for lane in ("socks", "redirect_wide")}
    if baseline is not None:
        baseline_arms = {lane: actual_arm(baseline, lane) for lane in arms}
        legacy = set()
        for arm in baseline_arms.values():
            condition = arm.splitlines()[0]
            legacy.update(re.findall(rb"ip=((?:[0-9]{1,3}\.){3}[0-9]{1,3})", condition))
        if len(legacy) != 1:
            raise ValueError("original_two_alternative_reference")
        legacy = legacy.pop().decode("ascii")
        reference_role = "paired_pinned_historical_positive_reference"
    else:
        # An independent QA constant, never derived from current product source,
        # installed configuration, selected relay or observed probe output.
        legacy = "192.0.2.20"
        reference_role = "current_source_CI_independent_TEST_NET_reference"
    bash = shutil.which(args.bash)
    keygen = shutil.which("ssh-keygen")
    if not bash or not keygen:
        raise ValueError("actual_bash_and_public_key_lookup_required")
    version = subprocess.run([bash, "--version"], stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, timeout=3, check=True).stdout
    match = re.search(rb"version ([0-9]+)\.", version)
    if not match or int(match[1]) < 4:
        raise ValueError("bash4_required_no_array_bypass")
    evidence = args.evidence.absolute()
    evidence.mkdir(mode=0o700, parents=False, exist_ok=False)
    evidence.chmod(0o700)
    private_write(evidence / "actual-script-before.bin", source)
    if baseline is not None:
        private_write(evidence / "original-script-reference.bin", baseline)
    raw_key = struct.pack(">I", 11) + b"ssh-ed25519" + struct.pack(">I", 32) + bytes(32)
    public_record = base64.b64encode(raw_key).decode("ascii")
    results = []

    def case(name, reference, expected_admission, observation=None, lane=None,
             expected_verdict=None):
        directory = evidence / name
        directory.mkdir(mode=0o700)
        tools = directory / "tools"
        tools.mkdir(mode=0o700)
        for tool in ("ssh", "scp"):
            private_write(tools / tool, b"#!/bin/sh\nprintf 'transport\n' >> \"$EGRESS_TRANSPORT_RECORD\"\nexit 44\n", True)
        public_lookup = ("#!/bin/sh\nprintf 'lookup\\n' >> \"$EGRESS_LOOKUP_RECORD\"\nexec " +
                         shlex.quote(keygen) + " \"$@\"\n").encode()
        private_write(tools / "ssh-keygen", public_lookup, True)
        key = directory / "key"
        known = directory / "known_hosts"
        private_write(key, b"inert-private-key-fixture-not-used-for-authentication\n")
        private_write(known, ("fixture-a ssh-ed25519 " + public_record + "\n").encode())
        home = directory / "home"
        home.mkdir(mode=0o700)
        env = {k: v for k, v in os.environ.items()
               if not k.startswith("VPS_") and k not in
               ("RELAY_HOST", "EXPECTED_EGRESS_IPS", "AEGIS_SSH_KNOWN_HOSTS",
                "SSH_AUTH_SOCK", "SSH_ASKPASS", "SSH_ASKPASS_REQUIRE", "DISPLAY")}
        env.update(PATH=str(tools) + os.pathsep + os.environ["PATH"], HOME=str(home),
                   RELAY_HOST="192.0.2.30", VPS_A_HOST="192.0.2.10",
                   VPS_A_SSH_ALIAS="fixture-a", VPS_A_SSH_KEY=str(key),
                   AEGIS_SSH_KNOWN_HOSTS=str(known), ARTIFACT_DIR=str(directory / "result"),
                   EGRESS_LOOKUP_RECORD=str(directory / "lookup.txt"),
                   EGRESS_TRANSPORT_RECORD=str(directory / "transport.txt"))
        if reference is not None:
            env["EXPECTED_EGRESS_IPS"] = reference
        suffix = b"printf 'fixture-admitted\\n'\n"
        if lane:
            env["EGRESS_FIXTURE_OBSERVATION"] = observation
            suffix += b'out="${EGRESS_FIXTURE_OBSERVATION}"\n' + arms[lane]
            suffix += ('printf "fixture-verdict=%s\\n" "${VERDICT[' + lane + ']:-NOT_RUN}"\n').encode()
        leaf = directory / "actual-leaf.sh"
        private_write(leaf, prefix + suffix, True)
        runtime, stdout, stderr = run_owned([bash, str(leaf)], env, directory)
        lookups = (directory / "lookup.txt").read_bytes().count(b"lookup\n") if (directory / "lookup.txt").exists() else 0
        transports = (directory / "transport.txt").read_bytes().count(b"transport\n") if (directory / "transport.txt").exists() else 0
        valid = (not runtime["timed_out"] and runtime["cleanup_error_type"] is None and
                 runtime["direct_parent_reaped_and_pipes_terminal"] and
                 args.script.resolve().read_bytes() == source and leaf.read_bytes() == prefix + suffix)
        admitted_witness = (runtime["exit_code"] == 0 and b"fixture-admitted\n" in stdout and
                            lookups == 1 and transports == 0 and (directory / "result").is_dir())
        admission_refusal_witness = (runtime["exit_code"] == 2 and stderr == REFUSAL and not stdout and
                                     lookups == 0 and transports == 0 and not (directory / "result").exists())
        # A recognized real source admission or its exact static refusal is a
        # semantic result. Unrelated SSH/environment/setup failures are INVALID.
        valid = valid and (admitted_witness or admission_refusal_witness)
        if expected_admission:
            passed = admitted_witness
            if lane:
                passed = passed and stdout.endswith(("fixture-verdict=" + expected_verdict + "\n").encode())
        else:
            # Original admits these cases and reaches actual first output and
            # public lookup. That is a valid causal FAIL, not fixture INVALID.
            passed = (runtime["exit_code"] == 2 and stderr == REFUSAL and not stdout and
                      lookups == 0 and transports == 0 and not (directory / "result").exists())
        result = {"case": name, "result": "PASS" if valid and passed else "FAIL" if valid else "INVALID",
                  "validity": valid, "expected_admission": expected_admission,
                  "comparator_lane": lane, "expected_verdict": expected_verdict,
                  "actual_public_lookup_invocations": lookups, "transport_invocations": transports,
                  "output_created": (directory / "result").exists(),
                  "actual_leaf_sha256": digest(leaf.read_bytes()),
                  "actual_prefix_sha256": digest(prefix),
                  "actual_original_arm_sha256": digest(arms[lane]) if lane else None, **runtime}
        private_write(directory / "receipt.json", (json.dumps(result, indent=2) + "\n").encode())
        results.append(result)
        print("EGRESS_CONTRACT " + name + " " + result["result"] + " validity=" + str(valid).lower())

    negatives = [
        ("missing", None), ("empty", ""), ("malformed", "not-an-ip"),
        ("leading_zero", "192.0.2.010"), ("out_of_range", "192.0.2.256"),
        ("ipv6", "::1"), ("whitespace", "192.0.2.10, 192.0.2.11"),
        ("newline", "192.0.2.10\n192.0.2.11"),
        ("leading_comma", ",192.0.2.10"), ("trailing_comma", "192.0.2.10,"),
        ("double_comma", "192.0.2.10,,192.0.2.11"),
        ("seventeen_entries", ",".join("192.0.2." + str(x) for x in range(10, 27))),
        ("over_byte_bound", "1" * 257),
    ]
    for name, reference in negatives:
        case("admission_" + name, reference, False)
    case("admission_single", "192.0.2.10", True)
    case("admission_two", "192.0.2.10,192.0.2.11", True)
    case("admission_sixteen", ",".join("192.0.2." + str(x) for x in range(10, 26)), True)
    for lane in arms:
        for name, ref, observation, verdict in [
            ("chosen_historical_alternative", legacy + ",192.0.2.30", "fl=fixture\nip=" + legacy + "\ncolo=FIX\n", "PASS"),
            ("chosen_relay_alternative", legacy + ",192.0.2.30", "fl=fixture\nip=192.0.2.30\ncolo=FIX\n", "PASS"),
            ("independent_first", "192.0.2.10,192.0.2.11", "fl=fixture\nip=192.0.2.10\ncolo=FIX\n", "PASS"),
            ("independent_second", "192.0.2.10,192.0.2.11", "ip=192.0.2.11", "PASS"),
            ("unchosen_legacy", "192.0.2.10,192.0.2.11", "ip=" + legacy + "\n", "PARTIAL"),
            ("unchosen_relay", "192.0.2.10,192.0.2.11", "ip=192.0.2.30\n", "PARTIAL"),
            ("mismatch", "192.0.2.10,192.0.2.11", "ip=192.0.2.99\n", "PARTIAL"),
            ("prefix", legacy + ",192.0.2.30", "xip=192.0.2.30\n", "PARTIAL"),
            ("suffix", legacy + ",192.0.2.30", "ip=192.0.2.30-extra\n", "PARTIAL"),
            ("duplicate", legacy + ",192.0.2.30", "ip=192.0.2.30\nip=192.0.2.30\n", "PARTIAL"),
            ("conflicting", legacy + ",192.0.2.30", "ip=192.0.2.30\nip=192.0.2.99\n", "PARTIAL"),
            ("absent", legacy + ",192.0.2.30", "fl=fixture\ncolo=FIX\n", "PARTIAL"),
        ]:
            case(lane + "_" + name, ref, True, observation, lane, verdict)
    summary = {"schema": "aegis_ubuntu_explicit_egress_contract_v1", "source_sha256": digest(source),
               "baseline_reference_sha256": digest(baseline) if baseline is not None else None,
               "positive_reference_role": reference_role, "fixture_sha256": digest(Path(__file__).read_bytes()),
               "actual_prefix_sha256": digest(prefix), "cases": results,
               "passed": sum(r["result"] == "PASS" for r in results),
               "failed": sum(r["result"] == "FAIL" for r in results),
               "invalid": sum(r["result"] == "INVALID" for r in results),
               "native_or_fleet_or_capture_or_egress_acceptance": False,
               "private_key_contents_read": False, "network": False,
               "cleanup_scope": "direct owned parent reaped and pipes terminal; independent outer supervisor required"}
    private_write(evidence / "summary.json", (json.dumps(summary, indent=2) + "\n").encode())
    print("EGRESS_CONTRACT_SUMMARY pass=" + str(summary["passed"]) + " fail=" + str(summary["failed"]) + " invalid=" + str(summary["invalid"]))
    return 2 if summary["invalid"] else 1 if summary["failed"] else 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print("EGRESS_CONTRACT_INVALID " + type(error).__name__)
        raise SystemExit(2)
