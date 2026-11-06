#!/usr/bin/env python3
"""No full proof script, lifecycle, native routing, transport or network is run.
Run this fixture under a separately owned outer process-group supervisor. Inner
bounds cover direct children; compiler descendants remain that outer owner's
responsibility. Any timeout/unconfirmed direct cleanup is INVALID, never RED.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import time
import tomllib

PREFIX_BOUND = 10.0
COMPILE_BOUND = 30.0
CLEANUP_BOUND = 4.0
OWNERS = (
    ("diag-fullwide-tun-udp.sh", "MASQUE_DIRECT", ': > "$EVENTS"'),
    ("proof-fullwide-tun-udp-direct.sh", "MASQUE_DIRECT", ': > "$EVENTS"; mkdir -p "$ART"'),
    ("proof-fullwide-tun-udp-perflow.sh", "MASQUE_DIRECT", ': > "$EVENTS"; mkdir -p "$ART"'),
    ("run-fullwide-tun-lifecycle-live.sh", "MASQUE_ORIGIN", 'mkdir -p "$ART"; : > "$EV"'),
    ("run-fullwide-tun-turnkey-live.sh", "MASQUE_DIRECT", 'mkdir -p "$ART" "$BK"'),
)
# All addresses are owned TEST-NET/documentation inputs. No transport is opened.
CASES = (
    ("missing", None), ("empty", ""),
    ("v4_first", "192.0.2.37:443"), ("v4_second", "198.51.100.83:8443"),
    ("v6_compressed", "[2001:db8::37]:443"),
    ("v6_full", "[2001:0db8:0000:0000:0000:0000:0000:0037]:8443"),
    ("v6_embedded", "[::ffff:192.0.2.37]:65535"),
    ("v6_scope_zero", "[2001:db8::37%0]:443"),
    ("v6_scope_numeric", "[2001:db8::37%17]:443"),
    ("v6_scope_max", "[2001:db8::37%4294967295]:443"),
    ("v6_scope_overflow", "[2001:db8::37%4294967296]:443"),
    ("v6_scope_named", "[2001:db8::37%eth0]:443"),
    ("port_leading_zero", "192.0.2.37:000443"),
    ("port_many_leading_zero", "192.0.2.37:" + "0" * 64 + "443"),
    ("hostname", "relay.invalid:443"), ("zero_port", "192.0.2.37:0"),
    ("all_zero_port", "192.0.2.37:00000"),
    ("overflow_port", "192.0.2.37:65536"),
    ("negative_port", "192.0.2.37:-1"), ("plus_port", "192.0.2.37:+443"),
    ("v4_leading_zero", "192.0.002.37:443"),
    ("v4_short", "192.0.2:443"), ("v4_overflow", "192.0.2.256:443"),
    ("v6_unbracketed", "2001:db8::37:443"),
    ("v6_duplicate_compression", "[2001::db8::37]:443"),
    ("v6_too_many_groups", "[1:2:3:4:5:6:7:8:9]:443"),
    ("v6_uncompressed_short", "[1:2:3:4:5:6:7]:443"),
    ("v6_compression_no_gap", "[1:2:3:4:5:6:7::8]:443"),
    ("v6_bad_embedded_v4", "[::ffff:192.0.002.37]:443"),
    ("leading_space", " 192.0.2.37:443"),
    ("trailing_space", "192.0.2.37:443 "),
    ("newline", "192.0.2.37:443\n"),
    ("quote", '192.0.2.37:443"'),
    ("missing_port", "192.0.2.37"),
)
ORACLE_SOURCE = r"""
use std::net::SocketAddr;
fn main() {
    for raw in std::env::args().skip(1) {
        let ready = raw.parse::<SocketAddr>().is_ok_and(|endpoint| endpoint.port() > 0);
        println!("{}", u8::from(ready));
    }
}
"""

class InvalidFixture(RuntimeError):
    pass

def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def owned_file(path, data=b""):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as out:
        out.write(data)

def run_owned(argv, cwd, env, work, label, bound=PREFIX_BOUND):
    stdout = work / (label + ".stdout")
    stderr = work / (label + ".stderr")
    owned_file(stdout); owned_file(stderr)
    started = time.monotonic()
    with stdout.open("wb") as out, stderr.open("wb") as err:
        try:
            child = subprocess.Popen(argv, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                                     stdout=out, stderr=err)
        except OSError as exc:
            raise InvalidFixture("required owned child failed to start") from exc
        pid = child.pid
        timed_out = False
        kill_error_type = None
        direct_reaped = False
        rc = None
        try:
            rc = child.wait(timeout=bound)
            direct_reaped = True
        except subprocess.TimeoutExpired:
            timed_out = True
            # The unreaped direct child retains its PID through this one kill.
            try:
                child.kill()
            except ProcessLookupError:
                pass
            except OSError as error:
                kill_error_type = type(error).__name__
            try:
                rc = child.wait(timeout=CLEANUP_BOUND)
                direct_reaped = True
            except subprocess.TimeoutExpired:
                pass
        record = {"case": label, "pid": pid, "exit_code": rc,
                  "elapsed_seconds": round(time.monotonic() - started, 6),
                  "timed_out": timed_out, "direct_child_reaped": direct_reaped,
                  "kill_error_type": kill_error_type,
                  "stdout_sha256": digest(stdout), "stderr_sha256": digest(stderr),
                  "descendant_cleanup_claim": False}
        # Retain a failed/invalid child's identity and observation before raising.
        owned_file(work / (label + ".record.json"),
                   (json.dumps(record, indent=2) + "\n").encode())
        if not direct_reaped:
            raise InvalidFixture("owned child cleanup unconfirmed")
        if timed_out:
            raise InvalidFixture("owned child exceeded original contract bound")
    return record, stdout.read_text(errors="replace"), stderr.read_text(errors="replace")

def original_prefix(text, marker):
    lines = text.splitlines(keepends=True)
    hits = [index for index, line in enumerate(lines) if line.rstrip("\n") == marker]
    if len(hits) != 1:
        raise InvalidFixture("original first-effect boundary missing or ambiguous")
    return "".join(lines[:hits[0]])

def rewrite_leaf(text):
    match = re.search(r"(?ms)^python3 - ([^\n]+) <<'PY'\n(.*?)^PY\n", text)
    if not match or '"$MASQUE_DIRECT"' not in match.group(1):
        raise InvalidFixture("actual local config rewrite leaf missing")
    return match.group(2), '"$MASQUE_CA"' in match.group(1)

def main():
    parser = argparse.ArgumentParser(description="Owned TEST-NET prefix and rewrite contract")
    parser.add_argument("--root", type=Path,
                        default=Path(__file__).resolve().parents[1])
    parser.add_argument("--phase", choices=("all", "prefix", "rewrite"), default="all")
    parser.add_argument("--evidence-dir", type=Path, required=True)
    args = parser.parse_args()
    root = args.root.resolve(strict=True)
    evidence = args.evidence_dir.resolve()
    evidence.mkdir(mode=0o700, parents=False, exist_ok=False)
    os.chmod(evidence, 0o700)
    records = []; failures = []; checks = []
    pins = {str(Path("scripts") / name): digest(root / "scripts" / name)
            for name, _, _ in OWNERS}
    env = os.environ.copy()
    env.pop("MASQUE_ORIGIN", None); env.pop("MASQUE_DIRECT", None)
    # Prefix QA never loads an inherited shell startup file before admission.
    env.pop("BASH_ENV", None); env.pop("ENV", None)
    rustc = os.environ.get("AEGIS_TEST_RUSTC") or shutil.which("rustc")
    if not rustc:
        raise InvalidFixture("actual Rust SocketAddr oracle compiler unavailable")
    # Preserve the rustc shim basename: resolving its symlink to rustup would
    # change dispatch to the manager instead of the actual compiler.
    compiler_entrypoint = Path(rustc).absolute()
    if not compiler_entrypoint.is_file():
        raise InvalidFixture("actual Rust compiler entrypoint unavailable")
    rustc = str(compiler_entrypoint)
    with tempfile.TemporaryDirectory(prefix="aegis-explicit-masque-") as temporary:
        work = Path(temporary).resolve(strict=True)
        os.chmod(work, 0o700)
        # All command output is retained privately. Nothing echoes endpoint data.
        oracle_source = work / "socketaddr.rs"; oracle = work / "socketaddr-oracle"
        owned_file(oracle_source, ORACLE_SOURCE.encode())
        record, _, _ = run_owned([rustc, "--edition=2021", str(oracle_source), "-o", str(oracle)],
                                 root, env, evidence, "compile-socketaddr-oracle", COMPILE_BOUND)
        records.append(record)
        if record["exit_code"] != 0 or not oracle.is_file():
            raise InvalidFixture("actual Rust SocketAddr oracle compilation failed")
        values = [value if value is not None else "" for _, value in CASES]
        record, output, _ = run_owned([str(oracle), *values], root, env, evidence,
                                     "actual-socketaddr-oracle")
        records.append(record)
        bits = output.splitlines()
        if record["exit_code"] != 0 or len(bits) != len(CASES) or any(bit not in ("0", "1") for bit in bits):
            raise InvalidFixture("actual Rust SocketAddr oracle output invalid")
        expected = {name: bit == "1" for (name, _), bit in zip(CASES, bits)}
        oracle_identity = {"source_sha256": digest(oracle_source),
                           "binary_sha256": digest(oracle),
                           "compiler_entrypoint_target_sha256": digest(compiler_entrypoint),
                           "compiler_entrypoint_basename": compiler_entrypoint.name}
        if args.phase in ("all", "prefix"):
            for name, variable, marker in OWNERS:
                text = (root / "scripts" / name).read_text()
                prefix = original_prefix(text, marker)
                script = work / (name + ".prefix")
                owned_file(script, (prefix + "\nprintf '%s\\n' 'AEGIS_PROOF_PREFIX_REACHED'\n"
                                  + 'printf "AEGIS_PROOF_ENDPOINT=%s\\n" "$' + variable + '"\n'
                                  + ': > "$AEGIS_TEST_PREFIX_EFFECT_WITNESS"\n').encode())
                for index, (case, value) in enumerate(CASES):
                    label = name.removesuffix(".sh") + "-" + case
                    witness = work / (label + ".effect")
                    child_env = env.copy(); child_env["AEGIS_TEST_PREFIX_EFFECT_WITNESS"] = str(witness)
                    argv = ["bash", str(script)]
                    if variable == "MASQUE_ORIGIN":
                        if value is not None:
                            child_env[variable] = value
                    elif value is not None:
                        argv.extend(["owned-unexecuted-binary-placeholder", value])
                    rec, stdout, stderr = run_owned(argv, root, child_env, evidence, label)
                    records.append(rec)
                    if rec["exit_code"] not in (0, 64):
                        raise InvalidFixture("actual shell prefix failed before semantic assertion")
                    entered = "AEGIS_PROOF_PREFIX_REACHED\n" in stdout
                    actual = re.findall(r"(?m)^AEGIS_PROOF_ENDPOINT=(.*)$", stdout)
                    if expected[case]:
                        good = rec["exit_code"] == 0 and entered and witness.exists() and actual == [value]
                    else:
                        good = (rec["exit_code"] == 64 and not entered and not witness.exists()
                                and stdout == "" and stderr == "explicit numeric MASQUE endpoint required\n")
                    checks.append({"owner": name, "case": case, "rust_socketaddr_admitted": expected[case],
                                   "pass": good, "effect_canary": entered,
                                   "selected_input_exact": actual == [value] if value is not None else False})
                    if not good:
                        failures.append(label)
        if args.phase in ("all", "rewrite"):
            # These are the exact two original embedded rewrite bodies, not copies
            # of their logic. We execute them only on fresh owned temporary configs.
            for name, value in (("diag-fullwide-tun-udp.sh", "192.0.2.37:443"),
                                ("proof-fullwide-tun-udp-perflow.sh", "[2001:db8::37]:8443")):
                text = (root / "scripts" / name).read_text(); leaf, with_ca = rewrite_leaf(text)
                config = work / (name + ".toml")
                owned_file(config, b'[ingress.wide]\nplatform_backend = "linux_redirect"\nipv6_tun_carried = false\n\n[relay]\nserver = "192.0.2.91:8443"\nmasque_server = "192.0.2.92:443"\n')
                source = work / (name + ".rewrite.py"); owned_file(source, leaf.encode())
                # Original code is Python, so the exact leaf uses the same interpreter
                # isolation added by the contract runner; no new product Python exists.
                argv = [os.sys.executable, "-I", str(source), str(config), value]
                ca = work / "owned-public-ca-placeholder.pem"
                if with_ca:
                    owned_file(ca, b"owned config-only placeholder; no TLS uses it\n")
                    argv.append(str(ca))
                rec, _, _ = run_owned(argv, root, env, evidence, name.removesuffix(".sh") + "-actual-rewrite")
                records.append(rec)
                rendered = tomllib.loads(config.read_text())
                good = (rec["exit_code"] == 0 and rendered["relay"]["masque_server"] == value
                        and rendered["ingress"]["wide"]["ipv6_tun_carried"] is True)
                if with_ca:
                    good = good and rendered["relay"]["masque_ca_cert"] == str(ca)
                checks.append({"owner": name, "case": "actual_temp_rewrite", "pass": good,
                               "actual_original_leaf_sha256": hashlib.sha256(leaf.encode()).hexdigest()})
                if not good:
                    failures.append(name + "-actual-rewrite")
    unchanged = all(digest(root / rel) == expected_sha for rel, expected_sha in pins.items())
    if not unchanged:
        raise InvalidFixture("input source changed during contract")
    result = {"schema_version": 1, "status": "PASS" if not failures else "ASSERTION_FAILURE",
              "source_sha256": pins, "source_unchanged": unchanged,
              "actual_rust_socketaddr_oracle": True, "oracle_identity": oracle_identity, "checks": checks,
              "passed": sum(check["pass"] for check in checks), "failed": len(failures),
              "invalid": 0, "failure_case_names": failures, "records": records,
              "prefix_bound_seconds": PREFIX_BOUND, "compile_bound_seconds": COMPILE_BOUND,
              "separate_direct_cleanup_bound_seconds": CLEANUP_BOUND,
              "native_lifecycle_or_transport_executed": False,
              "outer_owned_process_supervisor_required": True,
              "descendant_cleanup_claim": False}
    owned_file(evidence / "contract-result.json", (json.dumps(result, indent=2) + "\n").encode())
    print(json.dumps({"status": result["status"], "passed": result["passed"],
                      "failed": result["failed"], "invalid": 0,
                      "failure_case_names": failures}))
    return 0 if not failures else 1

if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (InvalidFixture, OSError, ValueError) as error:
        # Never turn missing compiler/owner/source admission into a regression PASS.
        print(json.dumps({"status": "INVALID_FIXTURE", "error_type": type(error).__name__}))
        raise SystemExit(2)
