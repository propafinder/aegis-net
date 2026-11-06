#!/usr/bin/env bash
# Offline actual-admission/helper contract. No remote lane, SSH or SFTP executes.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DRILL_SCRIPT="${AEGIS_SSH_CONTRACT_SCRIPT:-${SCRIPT_DIR}/aegis-full-ubuntu-live-drill.sh}"
BASH_FOR_CONTRACT="${BASH_FOR_SSH_CONTRACT:-${BASH:-bash}}"
python3 - "$DRILL_SCRIPT" "$BASH_FOR_CONTRACT" <<'PYQA'
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import struct
import subprocess
import sys
import tempfile
import time

SCRIPT = Path(sys.argv[1]).resolve(strict=True)
BASH = shutil.which(sys.argv[2])
KEYGEN = shutil.which("ssh-keygen")
if not BASH or not KEYGEN:
    print("SSH_CONTRACT_INVALID missing_bash_or_public_key_lookup")
    raise SystemExit(2)
try:
    version = subprocess.run([BASH, "--version"], stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, timeout=3, check=True).stdout
    match = re.search(rb"version (\d+)\.", version)
    if not match or int(match[1]) < 4:
        raise ValueError("bash4_required")
except Exception:
    print("SSH_CONTRACT_INVALID bash4_required")
    raise SystemExit(2)
source = SCRIPT.read_bytes()
boundary = b"# ---- pre-flight ----\n"
if source.count(boundary) != 1:
    print("SSH_CONTRACT_INVALID actual_leaf_boundary")
    raise SystemExit(2)
prefix = source[:source.index(boundary)]
if any(prefix.count(token) != 1 for token in
       (b"ssh_a() {", b"ssh_b() {", b"scp_a() {")):
    print("SSH_CONTRACT_INVALID actual_leaf_helpers")
    raise SystemExit(2)
requested = os.environ.get("AEGIS_SSH_CONTRACT_EVIDENCE")
if requested:
    evidence = Path(requested).absolute()
    evidence.mkdir(mode=0o700, parents=False, exist_ok=False)
else:
    evidence = Path(tempfile.mkdtemp(prefix="aegis-ssh-contract-"))
evidence.chmod(0o700)


def private_write(path, data, executable=False):
    with path.open("xb") as out:
        out.write(data)
    path.chmod(0o700 if executable else 0o600)


recorder = ("#!" + sys.executable + "\n" + r'''
import json, os, sys
from pathlib import Path
record = {"tool": Path(sys.argv[0]).name, "argv": sys.argv[1:]}
path = Path(os.environ["SSH_CONTRACT_RECORD"])
fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
with os.fdopen(fd, "a", encoding="utf-8") as out:
    out.write(json.dumps(record, separators=(",", ":")) + "\n")
# Do not execute the command carried by sshpass; all transport executables
# are recorders and this suite performs no SSH/key authentication/network.
raise SystemExit(42 if "fixture-failure" in sys.argv[1:] else 0)
''').encode()
# A synthetic public record is sufficient for real ssh-keygen -F lookup.
# Private-key fixture bytes are deliberately inert, never read by admission.
raw_key = struct.pack(">I", 11) + b"ssh-ed25519" + struct.pack(">I", 32) + bytes(32)
public_record = base64.b64encode(raw_key).decode()
common = (
    "-F", "/dev/null", "StrictHostKeyChecking=yes", "BatchMode=yes",
    "IdentitiesOnly=yes", "IdentityAgent=none", "PasswordAuthentication=no",
    "KbdInteractiveAuthentication=no", "GlobalKnownHostsFile=/dev/null", "Port=22",
)


def run_owned(argv, env, case):
    started = time.monotonic()
    process = subprocess.Popen(argv, env=env, cwd=case, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, start_new_session=True)
    pid = process.pid
    timed_out = False
    cleanup_confirmed = False
    try:
        stdout, stderr = process.communicate(timeout=10)
        cleanup_confirmed = process.returncode is not None
    except subprocess.TimeoutExpired:
        timed_out = True
        # Never signal a numeric group after reaping the owner. The outer
        # independent QA supervisor remains required for unexpected descendants.
        if process.poll() is None:
            try:
                os.killpg(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        try:
            stdout, stderr = process.communicate(timeout=4)
            cleanup_confirmed = process.returncode is not None
        except subprocess.TimeoutExpired:
            stdout, stderr = b"", b""
    private_write(case / "stdout.log", stdout)
    private_write(case / "stderr.log", stderr)
    return {"exit_code": process.returncode, "pid": pid,
            "elapsed_seconds": time.monotonic() - started,
            "timed_out": timed_out, "owned_parent_reaped_and_pipes_terminal": cleanup_confirmed,
            "stdout_sha256": hashlib.sha256(stdout).hexdigest(),
            "stderr_sha256": hashlib.sha256(stderr).hexdigest()}


results = []


def fixture(name, change=None, positive=False, downstream=False, relay_identity=False, relay_refusal=False):
    case = evidence / name
    case.mkdir(mode=0o700)
    tools = case / "tools"
    tools.mkdir(mode=0o700)
    for tool in ("ssh", "scp", "sshpass"):
        private_write(tools / tool, recorder, executable=True)
    os.symlink(KEYGEN, tools / "ssh-keygen")
    home = case / "home"
    home.mkdir(mode=0o700)
    key_a, key_b = case / "key-a", case / "key-b"
    known = case / "known_hosts"
    private_write(key_a, b"inert-private-key-fixture\n")
    private_write(key_b, b"inert-private-key-fixture\n")
    private_write(known, ("fixture-a ssh-ed25519 " + public_record + "\n" +
                          "fixture-b ssh-ed25519 " + public_record + "\n").encode())
    env = {k: v for k, v in os.environ.items()
           if not k.startswith("VPS_") and
           k not in ("AEGIS_SSH_KNOWN_HOSTS", "SSH_AUTH_SOCK", "SSH_ASKPASS",
                     "SSH_ASKPASS_REQUIRE", "DISPLAY", "RELAY_HOST")}
    env.update(PATH=str(tools) + os.pathsep + os.environ["PATH"],
               HOME=str(home), ARTIFACT_DIR=str(case / "result"),
               RELAY_HOST="192.0.2.30",
               EXPECTED_EGRESS_IPS="192.0.2.30,192.0.2.31",
               SSH_CONTRACT_RECORD=str(case / "transport.jsonl"),
               VPS_A_HOST="192.0.2.10", VPS_A_SSH_ALIAS="fixture-a",
               VPS_A_SSH_KEY=str(key_a), AEGIS_SSH_KNOWN_HOSTS=str(known),
               VPS_B_HOST="192.0.2.11" if downstream else "",
               VPS_B_SSH_ALIAS="fixture-b" if downstream else "",
               VPS_B_SSH_KEY=str(key_b) if downstream else "")
    if change:
        change(env, case, key_a, key_b, known)
    suffix = b"ssh_a fixture-control\n"
    if positive:
        suffix = b'''ssh_a fixture-control || exit 91
ssh_b fixture-control
b_rc=$?
if [[ -n "$VPS_B_HOST" ]]; then [[ "$b_rc" == 0 ]] || exit 92
else [[ "$b_rc" == 99 ]] || exit 93; fi
scp_a fixture-local-upload "root@${VPS_A_SSH_ALIAS}:/tmp/fixture-upload" || exit 94
scp_a "root@${VPS_A_SSH_ALIAS}:/tmp/fixture-download" fixture-local-download || exit 95
ssh_a fixture-failure
[[ "$?" == 42 ]] || exit 96
'''
    if relay_identity:
        # New exact supplied-identity control; existing nine case bodies and
        # all original SSH/SCP assertions remain unchanged.
        env["RELAY_IDENTITY_EXPECTED"] = env["RELAY_HOST"]
        suffix += b'[[ "$RELAY_HOST" == "$RELAY_IDENTITY_EXPECTED" ]] || exit 97\n'
    leaf = case / "actual-leaf.sh"
    private_write(leaf, prefix + suffix, executable=True)
    # Establish complete byte custody of the actual product leaf independently
    # of the target assertions. No hand-copied helper or admission parser is used.
    leaf_prefix_matches = leaf.read_bytes()[:len(prefix)] == prefix
    runtime = run_owned([BASH, str(leaf)], env, case)
    record_path = case / "transport.jsonl"
    records = [json.loads(line) for line in record_path.read_text().splitlines()] if record_path.exists() else []
    validity = leaf_prefix_matches and not runtime["timed_out"] and runtime["owned_parent_reaped_and_pipes_terminal"]
    reason = ""
    passed = False
    if not positive:
        passed = validity and runtime["exit_code"] == 2 and not records and not (case / "result").exists()
        if relay_refusal:
            # Distinguish this new seam from unrelated identity/dependency refusal.
            passed = passed and (case / "stderr.log").read_bytes() == b"FATAL: explicit canonical IPv4 RELAY_HOST required\n"
        reason = "early_static_refusal_before_output_and_transport"
    else:
        expected_tools = ["ssh", "ssh", "scp", "scp", "ssh"] if downstream else ["ssh", "scp", "scp", "ssh"]
        passed = validity and runtime["exit_code"] == 0 and [r["tool"] for r in records] == expected_tools
        for index, row in enumerate(records):
            args = row["argv"]
            is_b = downstream and index == 1
            alias = "fixture-b" if is_b else "fixture-a"
            address = "192.0.2.11" if is_b else "192.0.2.10"
            key = key_b if is_b else key_a
            required = common + (str(key), "HostName=" + address,
                                 "HostKeyAlias=" + alias,
                                 'UserKnownHostsFile=' + str(known))
            passed = passed and all(value in args for value in required)
            passed = passed and args[:2] == ["-F", "/dev/null"] and args[2:4] == ["-i", str(key)]
            passed = passed and not any("StrictHostKeyChecking=no" in value or "SYNTHETIC" in value for value in args)
            if row["tool"] == "ssh":
                passed = passed and "root@" + alias in args and "ConnectTimeout=10" in args
            else:
                # Preserve both actual SCP transfer directions and do not invent
                # a new SCP connection timeout absent from the original helper.
                passed = passed and "ConnectTimeout=10" not in args
                if "fixture-local-upload" in args:
                    passed = passed and args[-2:] == ["fixture-local-upload", "root@fixture-a:/tmp/fixture-upload"]
                else:
                    passed = passed and args[-2:] == ["root@fixture-a:/tmp/fixture-download", "fixture-local-download"]
        reason = "configured_key_and_pin_transport_argv_with_controlled_failure_propagation"
    result = {"case": name, "validity": validity,
              "result": "PASS" if passed else "FAIL" if validity else "INVALID",
              "assertion": reason, "transport_invocations": len(records),
              "actual_leaf_source_sha256": hashlib.sha256(source).hexdigest(),
              "actual_leaf_prefix_sha256": hashlib.sha256(prefix).hexdigest(),
              "private_key_contents_read": False, "native_ssh_authentication": False,
              "network_or_remote_lanes": False, **runtime}
    private_write(case / "receipt.json", (json.dumps(result, indent=2) + "\n").encode())
    results.append(result)
    print("SSH_CONTRACT " + name + " " + result["result"] +
          " transport=" + str(len(records)) + " validity=" + str(validity).lower())


fixture("legacy_password_without_identity", lambda env, case, a, b, known:
        (env.update(VPS_A_PASS="SYNTHETIC_PASSWORD_CANARY"), env.pop("VPS_A_SSH_KEY")))
fixture("missing_key", lambda env, case, a, b, known: env.pop("VPS_A_SSH_KEY"))
fixture("public_key_permissions", lambda env, case, a, b, known: a.chmod(0o644))
fixture("missing_known_hosts", lambda env, case, a, b, known: env.pop("AEGIS_SSH_KNOWN_HOSTS"))
fixture("missing_exact_host_pin", lambda env, case, a, b, known: env.update(VPS_A_SSH_ALIAS="unconfigured-alias"))
fixture("incomplete_downstream_identity", lambda env, case, a, b, known: env.update(VPS_B_HOST="192.0.2.11"))
def quoted_known_hosts(env, case, a, b, known):
    quoted = case / "known'hosts"
    known.rename(quoted)
    env["AEGIS_SSH_KNOWN_HOSTS"] = str(quoted)


fixture("quoted_known_hosts_path", quoted_known_hosts)
fixture("configured_A_and_both_scp_directions", positive=True)
fixture("configured_A_B_and_failure_propagation", positive=True, downstream=True)
fixture("configured_distinct_relay_identity", lambda env, case, a, b, known:
        env.update(RELAY_HOST="203.0.113.51"), positive=True, relay_identity=True)
fixture("missing_relay_before_output_and_transport", lambda env, case, a, b, known:
        env.pop("RELAY_HOST"), relay_refusal=True)
fixture("malformed_relay_before_output_and_transport", lambda env, case, a, b, known:
        env.update(RELAY_HOST="not-an-ip"), relay_refusal=True)
summary = {"schema": "aegis_offline_live_drill_ssh_contract_v1",
           "source": str(SCRIPT), "source_sha256": hashlib.sha256(source).hexdigest(),
           "actual_leaf_prefix_sha256": hashlib.sha256(prefix).hexdigest(),
           "fixture": "complete_actual_admission_and_helpers",
           "bash": BASH, "real_public_key_lookup": KEYGEN,
           "cases": results, "passed": sum(x["result"] == "PASS" for x in results),
           "failed": sum(x["result"] == "FAIL" for x in results),
           "invalid": sum(x["result"] == "INVALID" for x in results),
           "native_ssh_authentication": False, "network_or_remote_lanes": False,
           "cleanup_scope": "owned_parent_reaped_and_pipes_terminal; independent outer supervisor required for unexpected descendants"}
private_write(evidence / "summary.json", (json.dumps(summary, indent=2) + "\n").encode())
print("SSH_CONTRACT_SUMMARY pass=" + str(summary["passed"]) +
      " fail=" + str(summary["failed"]) + " invalid=" + str(summary["invalid"]))
raise SystemExit(2 if summary["invalid"] else 1 if summary["failed"] else 0)
PYQA
