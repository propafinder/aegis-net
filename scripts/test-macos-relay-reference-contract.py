#!/usr/bin/env python3
"""QA only: actual complete macOS early owner + original offline controls."""
import argparse
import hashlib
import json
import os
import pwd
from pathlib import Path
import re
import subprocess
import sys
import time

OWNERS = {
    "run-macos-utun-helper-fd-loop-lab.sh": "helper_route_reference",
    "run-macos-utun-w1-controlled-route-proof.sh": "helper_route_reference",
    "run-macos-utun-w2-stateful-tcp-edge-proof.sh": "helper_route_reference",
    "run-macos-utun-w2-tcp-flow-adapter-proof.sh": "helper_route_reference",
    "run-macos-utun-w3-local-relay-bridge-proof.sh": "metadata_only",
    "run-macos-utun-w3-relay-path-proof.sh": "metadata_only",
    "run-macos-utun-w5-controlled-external-relay-path.sh": "helper_route_reference_forwarding",
}
CONTROLS = [
    "test-macos-utun-w3-relay-path-proof-contract.sh",
    "test-macos-utun-w5-controlled-external-relay-path-contract.sh",
]
MAIN_LAUNCH_SOURCE = "macos-utun-main-launch.sh"
W0_OWNER = "run-macos-utun-helper-fd-loop-lab.sh"
INVALID = [
    ("missing", None),
    ("empty", ""),
    ("hostname", "relay.example.invalid"),
    ("ipv6", "2001:db8::20"),
    ("leading_zero", "192.0.02.20"),
    ("out_of_range", "192.0.2.256"),
    ("short", "192.0.20"),
    ("long", "192.0.2.20.1"),
    ("trailing_dot", "192.0.2.20."),
    ("prefix", "x192.0.2.20"),
    ("suffix", "192.0.2.20x"),
    ("newline", "192.0.2.20\n192.0.2.21"),
    ("space", "192.0.2.20 "),
    ("plus", "+192.0.2.20"),
]
VALID = [("independent_a", "192.0.2.20"), ("independent_b", "198.51.100.40")]
REFUSAL = b"AEGIS_RELAY_IP must be an explicit canonical IPv4 address\n"


def write_private(path, data):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with path.open("xb") as f:
        os.chmod(path, 0o600)
        f.write(data)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def private_env():
    env = os.environ.copy()
    for key in ["AEGIS_RELAY_IP", "AEGIS_MACOS_UTUN_HELPER", "BASH_ENV", "ENV", "SHELLOPTS", "BASHOPTS"]:
        env.pop(key, None)
    env["LC_ALL"] = "C"
    return env


def run_owned(command, env, timeout, directory):
    # Direct-child custody only. Root's independent same-session process-group
    # supervisor remains mandatory for descendants and unconfirmed cleanup.
    began = time.monotonic()
    process = subprocess.Popen(command, env=env, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE)
    timed_out = False
    cleanup_error = None
    try:
        stdout, stderr = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        process.kill()
        try:
            stdout, stderr = process.communicate(timeout=2)
        except subprocess.TimeoutExpired:
            stdout = b""
            stderr = b""
            cleanup_error = "direct_child_pipes_or_terminal_unconfirmed"
    write_private(directory / "stdout.raw", stdout)
    write_private(directory / "stderr.raw", stderr)
    info = {"exit_code": process.returncode, "timed_out": timed_out,
            "direct_parent_reaped": process.returncode is not None,
            "cleanup_error": cleanup_error,
            "elapsed_seconds": time.monotonic() - began,
            "descendant_quiescence_claim": False}
    write_private(directory / "process.json",
                  (json.dumps(info, indent=2) + "\n").encode())
    return info, stdout, stderr


def actual_prefix(source):
    lines = source.splitlines(keepends=True)
    hits = [i for i, line in enumerate(lines)
            if line == 'mkdir -p "${OUT_DIR}"\n']
    if not hits:
        raise ValueError("actual first output anchor unavailable")
    stop = hits[0]
    # Complete original prefix and its first actual output operation. No
    # rewritten ROOT or copied validator behavior in this fixture.
    prefix = "".join(lines[:stop + 1])
    if prefix.count('RELAY_IP="${AEGIS_RELAY_IP:-') != 1:
        raise ValueError("actual early relay owner missing or ambiguous")
    return prefix


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-root", type=Path,
                        default=Path(__file__).resolve().parents[1])
    parser.add_argument("--bash", required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    args = parser.parse_args()
    if not Path(args.bash).is_absolute():
        parser.error("actual Bash absolute path required")
    args.evidence.mkdir(mode=0o700)  # Existing evidence is refusal, never overwrite.
    records = []
    try:
        caller_uid = os.getuid()
        if caller_uid == 0 or caller_uid != os.geteuid():
            raise ValueError("actual matching non-root caller required")
        caller_account = pwd.getpwuid(caller_uid)
        if caller_account.pw_uid != caller_uid or not caller_account.pw_name:
            raise ValueError("actual caller account unavailable")
        env = private_env()
        vdir = args.evidence / "bash-version"
        vdir.mkdir(mode=0o700)
        v, out, err = run_owned([args.bash, "--version"], env, 3, vdir)
        match = re.search(rb"GNU bash, version ([0-9]+)\.", out)
        if (v["timed_out"] or v["cleanup_error"] or v["exit_code"] != 0
                or not match or int(match.group(1)) < 3):
            raise ValueError("actual compatible Bash unavailable")
        source_pins = {}
        for name in [*OWNERS, *CONTROLS, MAIN_LAUNCH_SOURCE]:
            p = args.source_root / "scripts" / name
            source_pins["scripts/" + name] = digest(p)
        for name, role in OWNERS.items():
            source = (args.source_root / "scripts" / name).read_text()
            prefix = actual_prefix(source)
            for label, value in INVALID + VALID:
                case = args.evidence / (name + "--" + label)
                case.mkdir(mode=0o700)
                leaf = case / "scripts" / name
                # The appended witness follows the original first output only.
                write_private(leaf, (prefix + '\nprintf \'%s\\n\' "$RELAY_IP" >"${OUT_DIR}/reference.txt"\n').encode())
                # Source only: the actual launcher and UID guard run before
                # address admission. The prefix never calls its main launcher.
                write_private(case / "scripts" / MAIN_LAUNCH_SOURCE,
                              (args.source_root / "scripts" / MAIN_LAUNCH_SOURCE).read_bytes())
                env = private_env()
                env["AEGIS_USER"] = caller_account.pw_name
                if name == W0_OWNER:
                    # Regular executable DATA admits only W0's path preflight.
                    # It has no interpreter or helper implementation and the
                    # extracted prefix must never execute it.
                    helper = case / "never-executed-helper-data"
                    write_private(helper, b"offline helper prerequisite data; never execute\n")
                    os.chmod(helper, 0o700)
                    env["AEGIS_MACOS_UTUN_HELPER"] = str(helper)
                if value is not None:
                    env["AEGIS_RELAY_IP"] = value
                output = case / "out"
                process, stdout, stderr = run_owned(
                    [args.bash, "--noprofile", "--norc", str(leaf), str(output)],
                    env, 5, case)
                confirmed = (not process["timed_out"] and not process["cleanup_error"]
                             and process["direct_parent_reaped"])
                if label.startswith("independent_"):
                    admitted = (process["exit_code"] == 0 and output.is_dir()
                                and (output / "reference.txt").read_bytes()
                                == (value + "\n").encode()) if confirmed and (output / "reference.txt").is_file() else False
                    passed = admitted
                    validity = confirmed and process["exit_code"] in [0, 2]
                else:
                    refused = process["exit_code"] == 2 and stderr == REFUSAL
                    no_output = not output.exists()
                    legacy_admitted = (process["exit_code"] == 0 and output.is_dir()
                                       and (output / "reference.txt").is_file())
                    passed = refused and no_output and not stdout
                    # Only actual early refusal or actual original first output
                    # establishes validity; unrelated shell/env failures INVALID.
                    validity = confirmed and (refused or legacy_admitted)
                status = "PASS" if validity and passed else "FAIL" if validity else "INVALID"
                record = {"name": name + "::" + label, "owner_role": role,
                          "status": status, "actual_prefix_source_sha256": source_pins["scripts/" + name],
                          "first_output_created": output.exists(), "process": process}
                records.append(record)
                write_private(case / "receipt.json", (json.dumps(record, indent=2) + "\n").encode())
                print("MAC_RELAY_CASE " + record["name"] + " " + status, flush=True)
        # Original whole offline controls run with their fixture-only initializer
        # and every original evidence/negative assertion preserved in both roles.
        mini = args.evidence / "whole-original-controls"
        mini.mkdir(mode=0o700)
        for name in [*OWNERS, *CONTROLS, MAIN_LAUNCH_SOURCE]:
            write_private(mini / "scripts" / name,
                          (args.source_root / "scripts" / name).read_bytes())
        for name in CONTROLS:
            case = args.evidence / ("whole--" + name)
            case.mkdir(mode=0o700)
            env = private_env()
            env["AEGIS_USER"] = caller_account.pw_name
            # Original complete controls invoke the literal bash command;
            # resolve it from the selected real Bash directory, never a mock.
            env["PATH"] = str(Path(args.bash).parent) + os.pathsep + env.get("PATH", "")
            env["TMPDIR"] = str(case)
            process, stdout, stderr = run_owned(
                [args.bash, "--noprofile", "--norc", str(mini / "scripts" / name)],
                env, 20, case)
            validity = (not process["timed_out"] and not process["cleanup_error"]
                        and process["direct_parent_reaped"])
            # Preserve the original complete shell exit as authoritative: no
            # synthetic skip/recording mock may replace its original assertions.
            status = "PASS" if validity and process["exit_code"] == 0 else "FAIL" if validity else "INVALID"
            record = {"name": "whole_original::" + name, "status": status,
                      "source_sha256": source_pins["scripts/" + name], "process": process,
                      "native_acceptance": False}
            records.append(record)
            write_private(case / "receipt.json", (json.dumps(record, indent=2) + "\n").encode())
            print("MAC_RELAY_CASE " + record["name"] + " " + status, flush=True)
        totals = {key: sum(x["status"] == key for x in records)
                  for key in ["PASS", "FAIL", "INVALID"]}
        if len(records) != 114:
            raise ValueError("complete actual scenario inventory missing")
        summary = {"schema": 1, "records": records, "checks": len(records),
                   "totals": totals, "source_pins": source_pins,
                   "real_Bash_executable": args.bash,
                   "Bash_executable_sha256": digest(Path(args.bash)),
                   "QA_only": True, "native_acceptance": False,
                   "outer_process_group_supervisor_required": True,
                   "metadata_owners_not_egress_or_certificate_proof": True}
        write_private(args.evidence / "summary.json",
                      (json.dumps(summary, indent=2) + "\n").encode())
        return 0 if totals == {"PASS": 114, "FAIL": 0, "INVALID": 0} else 1
    except Exception as error:
        write_private(args.evidence / "invalid.json",
                      (json.dumps({"status": "INVALID", "error_type": type(error).__name__,
                                   "prior_records": len(records)}) + "\n").encode())
        print("MAC_RELAY_ENVIRONMENT INVALID", flush=True)
        return 2


if __name__ == "__main__":
    sys.exit(main())
