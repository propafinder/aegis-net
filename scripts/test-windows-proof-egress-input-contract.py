#!/usr/bin/env python3
"""Exercise the actual Windows proof admission prefixes, without native proof claims."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import time

OWNERS = {
    "service": ("scripts/windows/run-windows-wide-service-persistence-proof.ps1", "New-Item -ItemType Directory -Force -Path $ArtifactRoot | Out-Null"),
    "browser": ("scripts/windows/run-wfp-controlled-browser-proof.ps1", "New-Item -ItemType Directory -Force -Path $ArtifactRoot | Out-Null"),
    "reboot": ("scripts/windows/run-windows-wide-service-reboot-proof.ps1", "if (!(Test-Path $winctl)) {"),
}
MARKER = "AUDIT23_PREFIX_VALIDITY "
REFUSAL = b"ExpectedRelayEgressIp must be an explicit IP address"
CASE_SECONDS = 10
CLEANUP_SECONDS = 4


def digest(data):
    return hashlib.sha256(data).hexdigest()


def private_write(path, data):
    path.write_bytes(data)
    path.chmod(0o600)


def write_ci_safe_summary(output, final):
    """Retain bounded admission metadata without exporting private prefixes."""
    safe_root = output / "ci-safe"
    safe_root.mkdir(mode=0o700)
    safe_cases = []
    for case in final["cases"]:
        role, name = case["role"], case["case"]
        if role not in OWNERS or name not in ("explicit_a", "explicit_b",
                                               "missing", "malformed"):
            raise ValueError("unexpected_ci_safe_case")
        process = case["process"]
        code = process["returncode"]
        elapsed = process["elapsed_seconds"]
        safe = {
            "schema_version": 1, "role": role, "case": name,
            "positive": bool(case["positive"]),
            "target_passed": bool(case["target_passed"]),
            "process_valid": bool(process["reaped"] and
                                  not process["timeout"] and
                                  not process["cleanup_error"]),
            "reaped": bool(process["reaped"]),
            "timeout": bool(process["timeout"]),
            "cleanup_error": bool(process["cleanup_error"]),
            "returncode": code if type(code) is int and -4095 <= code <= 4095
                          else None,
            "elapsed_ms": min(30000, max(0, int(elapsed * 1000)))
                          if type(elapsed) in (int, float) else None,
            "output_mutation_absent": bool(case["output_mutation_absent"]),
            "admission_observed": bool(case["admission_observed"]),
            "static_refusal_observed": bool(case["static_refusal_observed"]),
        }
        case_root = safe_root / (role + "-" + name)
        case_root.mkdir(mode=0o700)
        private_write(case_root / "receipt.json",
                      (json.dumps(safe, sort_keys=True) + "\n").encode())
        safe_cases.append(safe)
    safe_final = {
        "schema_version": 1,
        "scope": "actual_parameter_admission_prefix_only",
        "native_acceptance": "not_exercised",
        "status": final["status"],
        "case_count": len(safe_cases),
        "passed_case_count": sum(case["target_passed"] for case in safe_cases),
        "expected_case_count": 12,
        "sources_unchanged": bool(final.get("sources_unchanged", False)),
        "cleanup_confirmed": bool(final.get("cleanup_confirmed", False)),
    }
    private_write(safe_root / "final.json",
                  (json.dumps(safe_final, sort_keys=True) + "\n").encode())


def execute_owned(argv, cwd):
    owner = None
    start = time.monotonic()
    try:
        options = {"start_new_session": True} if os.name != "nt" else {
            "creationflags": subprocess.CREATE_NEW_PROCESS_GROUP
        }
        owner = subprocess.Popen(argv, cwd=cwd, stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE, stdin=subprocess.DEVNULL,
                                 **options)
        try:
            out, err = owner.communicate(timeout=CASE_SECONDS)
            return {"returncode": owner.returncode, "pid": owner.pid,
                    "reaped": True, "timeout": False, "cleanup_error": False,
                    "elapsed_seconds": time.monotonic() - start}, out, err
        except (subprocess.TimeoutExpired, BaseException) as failure:
            cleanup_end = time.monotonic() + CLEANUP_SECONDS
            kill_error = False
            try:
                if owner.poll() is None:
                    owner.kill()
            except OSError:
                kill_error = True
            try:
                remaining = max(0, cleanup_end - time.monotonic())
                out, err = owner.communicate(timeout=remaining)
                reaped = owner.returncode is not None
            except (subprocess.TimeoutExpired, OSError):
                out, err = b"", b""
                reaped = False
            return {"returncode": owner.returncode, "pid": owner.pid,
                    "reaped": reaped, "timeout": isinstance(failure, subprocess.TimeoutExpired),
                    "cleanup_error": kill_error or not reaped,
                    "exception": type(failure).__name__,
                    "elapsed_seconds": time.monotonic() - start}, out, err
    except OSError as failure:
        return {"returncode": None, "pid": owner.pid if owner else None,
                "reaped": owner is None, "timeout": False, "cleanup_error": False,
                "exception": type(failure).__name__,
                "elapsed_seconds": time.monotonic() - start}, b"", b""


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--powershell", default=None)
    args = parser.parse_args()
    root = args.repo_root.resolve()
    output = args.output_dir.resolve()
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    powershell = args.powershell or shutil.which("pwsh")
    final = {"schema_version": 1, "scope": "actual_parameter_admission_prefix_only",
             "native_acceptance": "not_exercised", "cases": [], "source_pins": {},
             "descendant_cleanup": "no_universal_OS_guarantee; outer_CI_or_root_supervisor_required"}
    if not powershell or not Path(powershell).is_file():
        final.update(status="INVALID", reason="real_powershell_runtime_unavailable",
                     cleanup_confirmed=True)
        private_write(output / "final.json", (json.dumps(final, indent=2) + "\n").encode())
        write_ci_safe_summary(output, final)
        print(json.dumps({"status": "INVALID", "reason": final["reason"]}))
        return 2
    invalid = False
    failed = False
    initial = {}
    try:
        for role, (relative, boundary) in OWNERS.items():
            data = (root / relative).read_bytes()
            initial[relative] = digest(data)
            source = data.decode("utf-8")
            if source.count(boundary) != 1:
                raise ValueError("owned prefix boundary unavailable")
            prefix = source[:source.index(boundary)]
            source_name = output / (role + "-actual-prefix.ps1")
            body = prefix + "\n[Console]::Out.WriteLine('" + MARKER + "' + (@{ admitted = $true; expected = $ExpectedRelayEgressIp } | ConvertTo-Json -Compress))\n"
            private_write(source_name, body.encode())
            final["source_pins"][relative] = {"whole_sha256": initial[relative],
                                               "actual_prefix_sha256": digest(prefix.encode())}
            controls_passed = 0
            cases = [("explicit_a", "192.0.2.81", True),
                     ("explicit_b", "198.51.100.82", True),
                     ("missing", None, False),
                     ("malformed", "not-an-ip", False)]
            for name, expected, positive in cases:
                case_dir = output / (role + "-" + name)
                case_dir.mkdir(mode=0o700)
                artifacts = case_dir / "must-remain-absent"
                argv = [str(powershell), "-NoProfile", "-NonInteractive", "-File",
                        str(source_name), "-RepoRoot", str(case_dir),
                        "-ArtifactRoot", str(artifacts)]
                if expected is not None:
                    argv += ["-ExpectedRelayEgressIp", expected]
                receipt, stdout, stderr = execute_owned(argv, case_dir)
                private_write(case_dir / "stdout.private", stdout)
                private_write(case_dir / "stderr.private", stderr)
                markers = [line[len(MARKER):] for line in stdout.decode("utf-8", errors="replace").splitlines()
                           if line.startswith(MARKER)]
                value = json.loads(markers[0]) if len(markers) == 1 else None
                actual_output_absent = not artifacts.exists()
                process_valid = receipt["reaped"] and not receipt["timeout"] and not receipt["cleanup_error"]
                if positive:
                    passed = process_valid and receipt["returncode"] == 0 and actual_output_absent and value == {"admitted": True, "expected": expected}
                    if passed:
                        controls_passed += 1
                    else:
                        invalid = True
                else:
                    passed = (process_valid and receipt["returncode"] not in (None, 0)
                              and actual_output_absent and not markers and REFUSAL in stderr)
                    if not process_valid or controls_passed != 2:
                        invalid = True
                    elif not passed:
                        # Expected RED requires admission observed after the real positive controls.
                        if receipt["returncode"] == 0 and value and value.get("admitted") is True and actual_output_absent:
                            failed = True
                        else:
                            invalid = True
                case = {"role": role, "case": name, "positive": positive,
                        "positive_controls_completed": controls_passed,
                        "target_passed": passed, "output_mutation_absent": actual_output_absent,
                        "admission_observed": bool(value and value.get("admitted") is True),
                        "static_refusal_observed": REFUSAL in stderr,
                        "stdout_sha256": digest(stdout), "stderr_sha256": digest(stderr),
                        "process": receipt}
                final["cases"].append(case)
                private_write(case_dir / "receipt.json", (json.dumps(case, indent=2) + "\n").encode())
    except (OSError, ValueError, UnicodeError, json.JSONDecodeError) as failure:
        invalid = True
        final["exception"] = type(failure).__name__
    final["sources_unchanged"] = all((root / path).is_file() and digest((root / path).read_bytes()) == sha for path, sha in initial.items())
    final["cleanup_confirmed"] = all(case["process"]["reaped"] and not case["process"]["cleanup_error"] for case in final["cases"])
    if not final["sources_unchanged"] or not final["cleanup_confirmed"] or len(final["cases"]) != 12:
        invalid = True
    final["status"] = "INVALID" if invalid else "FAIL" if failed else "PASS"
    final["passed_case_count"] = sum(case["target_passed"] for case in final["cases"])
    final["case_count"] = len(final["cases"])
    private_write(output / "final.json", (json.dumps(final, indent=2) + "\n").encode())
    write_ci_safe_summary(output, final)
    print(json.dumps({"status": final["status"], "passed_case_count": final["passed_case_count"],
                      "case_count": final["case_count"], "native_acceptance": final["native_acceptance"]}))
    return 2 if invalid else 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
