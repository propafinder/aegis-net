#!/usr/bin/env bash
# Inert regression: the sudo environment boundary must not drop metadata trust.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
python3 "${ROOT}/scripts/test-smoke-root-state-client.py"
python3 - "${ROOT}" <<'PY'
import os, pathlib, re, subprocess, sys, tempfile
root = pathlib.Path(sys.argv[1])
checked = 0
with tempfile.TemporaryDirectory(prefix="aegis-smoke-binding-") as name:
    fixture = pathlib.Path(name)
    (fixture / "scripts").mkdir()
    for kind in ("tproxy", "redirect"):
        target = fixture / "scripts" / ("setup-wide-linux-" + kind + ".sh")
        target.write_text('''#!/usr/bin/env bash
set -eu
test "${AEGIS_ROOT_STATE_CLIENT:-}" = "$EXPECTED_SMOKE_CLIENT"
test "${AEGIS_CLIENT_BIN:-}" = "$EXPECTED_SMOKE_CLIENT"
if [ "$EXPECTED_KIND" = tproxy ]; then test "${AEGIS_MEASURE_BIN:-}" = "$EXPECTED_SMOKE_CLIENT"; fi
printf '%s\\n' "$1"
''')
        source = (root / "scripts" / ("smoke-wide-linux-" + kind + ".sh")).read_text()
        lines = source.splitlines()
        commands = []
        for i, line in enumerate(lines):
            stripped = line.strip()
            if not (stripped.startswith("sudo ") or stripped.startswith("if ! sudo ")):
                continue
            group = []
            for following in lines[i:i+25]:
                group.append(following.strip())
                if not following.rstrip().endswith("\\"):
                    break
            command = "\n".join(group)
            match = re.search(r'bash "\$\{ROOT\}/scripts/setup-wide-linux-' + kind + r'\.sh" (apply|teardown|status|doctor)', command)
            if match:
                commands.append((match[1], command[:match.end()].removeprefix("if ! ")))
        assert len(commands) == (4 if kind == "tproxy" else 3), (kind, commands)
        for action, command in commands:
            env = dict(os.environ)
            for variable in re.findall(r"\$\{([A-Z][A-Z0-9_]*)", command):
                env[variable] = "fixture"
            env.update(ROOT=str(fixture), EXPECTED_KIND=kind, AEGIS_MEASURE_BIN="/owned/staged/aegis-client", AEGIS_ROOT_STATE_CLIENT="/owned/staged/aegis-client",
                       AEGIS_CLIENT_BIN="/owned/staged/aegis-client",
                       EXPECTED_SMOKE_CLIENT="/owned/staged/aegis-client")
            prefix = '''set -eu
sudo() {
  if [ "${1:-}" = -n ]; then shift; fi
  # Deliberately discard the caller environment as real nested sudo does.
  env -i PATH="$PATH" EXPECTED_SMOKE_CLIENT="$EXPECTED_SMOKE_CLIENT" EXPECTED_KIND="$EXPECTED_KIND" "$@"
}
'''
            result = subprocess.run(["bash"], input=prefix+command+"\n", text=True,
                                    env=env, capture_output=True, timeout=10)
            assert result.returncode == 0 and result.stdout.strip() == action, (kind, action, result.stderr)
            # A caller exporting the binding alone is insufficient. Reproduce
            # the old invocation by removing both explicit assignment lines.
            broken = re.sub(r'AEGIS_(?:ROOT_STATE_CLIENT|CLIENT_BIN|MEASURE_BIN)="[^"]*"\s*\\\n\s*', "", command)
            negative = subprocess.run(["bash"], input=prefix+broken+"\n", text=True,
                                      env=env, capture_output=True, timeout=10)
            assert negative.returncode != 0, (kind, action, "lost-binding regression did not fail")
            checked += 1
print(f"smoke metadata sudo binding: {checked} actual invocation blocks PASS; {checked} lost-binding negatives PASS (inert)")
PY

python3 - "${ROOT}" <<'CARGO_PY'
import json, os, pathlib, re, shutil, subprocess, sys, tempfile

root = pathlib.Path(sys.argv[1])
wrapper = root / "scripts/lib/smoke-root-state-client.sh"
tproxy = (root / "scripts/smoke-wide-linux-tproxy.sh").read_text()
redirect = (root / "scripts/smoke-wide-linux-redirect.sh").read_text()
assert '${ROOT}/target/debug/' not in tproxy + redirect, "stale default target lookup remains"

def function(source, name):
    match = re.search(r'^' + re.escape(name) + r'\(\) \{\n.*?^\}', source, re.M | re.S)
    assert match, name
    return match.group(0) + "\n"

measure_functions = function(tproxy, "run_aegis_measure") + function(tproxy, "ensure_aegis_measure_run_bin")
client_initial = next(line for line in tproxy.splitlines() if line.startswith("CLIENT_BIN_OVERRIDE="))
client_built = next(line.strip() for line in tproxy.splitlines()
                    if 'CLIENT_BIN_OVERRIDE=' in line and '/debug/aegis-client' in line)
server_program = re.search(r'^\s*("[^"\n]+/debug/aegis-server") --config', tproxy, re.M).group(1)
redirect_stage = next(line for line in redirect.splitlines() if line.startswith("aegis_smoke_stage_root_state_client "))
resolution = re.search(r'^SMOKE_CARGO_TARGET_DIRECTORY=""\nif .*?^fi\n', tproxy, re.M | re.S).group(0)
actual_cargo = shutil.which("cargo")
assert actual_cargo, "cargo is required for offline metadata-only fixture checks"

with tempfile.TemporaryDirectory(prefix="aegis-smoke-cargo-path-") as name:
    fixture = pathlib.Path(name).resolve()
    project = fixture / "project"
    project.mkdir()
    (project / ".cargo").mkdir()
    (project / "Cargo.toml").write_text('[package]\nname="smoke-metadata-fixture"\nversion="0.0.0"\nedition="2021"\n[lib]\npath="lib.rs"\n')
    (project / "lib.rs").write_text("// Offline metadata fixture: never compiled.\n")
    bins = fixture / "bin"
    bins.mkdir()
    cargo_guard = bins / "cargo"
    cargo_guard.write_text('''#!/usr/bin/env python3
import json, os, subprocess, sys
if os.environ.get("FORBID_CARGO") == "1":
    raise SystemExit("prebuilt HTTP path called cargo")
assert sys.argv[1] == "metadata", "no builds or runtime cargo calls are permitted"
assert "--offline" in sys.argv and "--no-deps" in sys.argv
assert os.getcwd() == os.environ["FIXTURE_ROOT"], "metadata must run from ROOT"
if "FAKE_METADATA" in os.environ:
    print(os.environ["FAKE_METADATA"])
    raise SystemExit(int(os.environ.get("FAKE_CARGO_EXIT", "0")))
raise SystemExit(subprocess.run([os.environ["ACTUAL_CARGO"], *sys.argv[1:]]).returncode)
''')
    cargo_guard.chmod(0o755)

    def executable(path):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text('#!/usr/bin/env bash\nprintf "%s\\n" "$0"\n')
        path.chmod(0o755)

    for leaf in ("aegis-client", "aegis-measure", "aegis-server"):
        executable(project / "target/debug" / leaf)  # Existing stale default must never win.
    prebuilt_client = fixture / "prebuilt client"
    prebuilt_measure = fixture / "prebuilt measure"
    executable(prebuilt_client)
    executable(prebuilt_measure)
    env = dict(os.environ)
    for key in ("CARGO_TARGET_DIR", "CARGO_BUILD_TARGET_DIR", "CARGO_BIN", "AEGIS_CLIENT_BIN",
                "AEGIS_MEASURE_BIN", "AEGIS_MEASURE_RUN_BIN", "RUSTUP_TOOLCHAIN"):
        env.pop(key, None)
    env.update(ROOT=str(project), FIXTURE_ROOT=str(project), WRAPPER=str(wrapper),
               ACTUAL_CARGO=actual_cargo, PATH=str(bins) + os.pathsep + env["PATH"],
               SMOKE_PROTOCOL="http", CLIENT_BIN_OVERRIDE="")
    prefix = 'set -euo pipefail\n. "$WRAPPER"\n' + measure_functions
    stage_stub = 'aegis_smoke_stage_root_state_client() { printf "%s\\n" "$1"; }\n'

    def run(code, run_env):
        return subprocess.run(["bash"], input=prefix + code, text=True, cwd=fixture,
                              env=run_env, capture_output=True, timeout=30)

    # Actual Cargo metadata honors config, absolute env override, and a relative
    # env override from ROOT even when this harness starts in another directory.
    config_target = project / "configured target"
    (project / ".cargo/config.toml").write_text('[build]\ntarget-dir="configured target"\n')
    cases = [("config", None, config_target),
             ("absolute-env", str(fixture / "environment target"), fixture / "environment target"),
             ("relative-env", "relative target", project / "relative target")]
    for label, target_env, target in cases:
        for leaf in ("aegis-client", "aegis-measure", "aegis-server"):
            executable(target / "debug" / leaf)
        selected_env = dict(env)
        if target_env is not None:
            selected_env["CARGO_TARGET_DIR"] = target_env
        code = (resolution + 'printf "%s\\n" "$SMOKE_CARGO_TARGET_DIRECTORY"\n'
                + 'ensure_aegis_measure_run_bin\nprintf "%s\\n" "$AEGIS_MEASURE_RUN_BIN"\n'
                + 'run_aegis_measure --inert-path-probe\n' + client_built
                + '\nprintf "%s\\n" "$CLIENT_BIN_OVERRIDE"\n' + server_program
                + ' --inert-path-probe\n' + stage_stub + redirect_stage + "\n")
        result = run(code, selected_env)
        expected = [str(target), str(target / "debug/aegis-measure"), str(target / "debug/aegis-measure"),
                    str(target / "debug/aegis-client"), str(target / "debug/aegis-server"), str(target / "debug/aegis-client")]
        assert result.returncode == 0 and result.stdout.splitlines() == expected, (label, result.stdout, result.stderr)

    # Existing fully prebuilt HTTP flow must never initialize Cargo or Rustup.
    selected_env = dict(env, FORBID_CARGO="1", AEGIS_CLIENT_BIN=str(prebuilt_client),
                        AEGIS_MEASURE_BIN=str(prebuilt_measure))
    code = (client_initial + "\n" + resolution + function(tproxy, "validate_client_bin_override")
            + 'validate_client_bin_override\nprintf "%s\\n" "$CLIENT_BIN_OVERRIDE"\n'
            + 'ensure_aegis_measure_run_bin\nprintf "%s\\n" "$AEGIS_MEASURE_RUN_BIN"\n'
            + 'run_aegis_measure --inert-path-probe\n' + stage_stub + redirect_stage + "\n")
    result = run(code, selected_env)
    assert result.returncode == 0 and result.stdout.splitlines() == [str(prebuilt_client), str(prebuilt_measure),
            str(prebuilt_measure), str(prebuilt_client)], ("prebuilt", result.stdout, result.stderr)

    # Malformed metadata and a failing Cargo producer must not fall back to the
    # stale ROOT/target even if the producer printed a plausible absolute path.
    for payload, exit_code in [('{}', '0'), ('{"target_directory":"relative"}', '0'),
                               ('not-json', '0'), (json.dumps({"target_directory": str(config_target)}), '7')]:
        failed_env = dict(env, FAKE_METADATA=payload, FAKE_CARGO_EXIT=exit_code)
        result = run('aegis_smoke_cargo_target_directory\n', failed_env)
        assert result.returncode != 0, (payload, result.stdout, result.stderr)
print("smoke Cargo paths: 3 config/env cases, prebuilt HTTP without Cargo, 4 metadata refusal cases PASS (no build/network/native)")
CARGO_PY
