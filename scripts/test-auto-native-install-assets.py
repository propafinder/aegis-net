#!/usr/bin/env python3
"""Exercise the exact passive Linux AUTO installer copy with disposable paths."""

from pathlib import Path
import json
import re
import shutil
import stat
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
MODULES = (
    "aegis_installer_auto_v2.py",
    "aegis_auto_capture.py",
    "aegis_auto_capture_topology.py",
    "aegis_auto_endpoint.py",
    "aegis_auto_guard_policy.py", "aegis_auto_foreign_policy.py", "aegis_auto_foreign_monitor.py", "aegis_auto_ufw_pins.json", "aegis_initrd_policy.py", "aegis_initrd_classic.py",
    "aegis_auto_guardian.py",
    "aegis_auto_guardian_watchdog.py",
    "aegis_auto_terminal_witness.py",
    "aegis_auto_terminal_boot_store.py",
    "aegis_auto_terminal_register.py",
    "aegis_auto_boot_transition.py",
    "aegis_auto_launch.py",
    "aegis_auto_native_witness.py",
    "aegis_auto_sink.py",
    "aegis_auto_trace_rollback.py",
    "aegis_auto_witness_topology.py",
)
UNITS = (
    "aegis-auto-config.service",
    "aegis-auto-capture-topology.service",
    "aegis-auto-guardian-watchdog.service",
    "aegis-auto-guardian.service",
    "aegis-auto-terminal-a@.service",
    "aegis-auto-terminal-b@.service",
    "aegis-auto-terminal-observer.service",
    "aegis-auto-terminal-transition.service",
    "aegis-auto-trace-rollback-actor.service",
    "aegis-auto-trace-rollback.service",
    "aegis-auto-trace-rollback.timer",
    "aegis-auto-witness-topology.service",
    "aegis-foreign-policy-monitor.service",
    "aegis-device-dhcp-refresh.service",
    "aegis-device-dhcp-refresh.timer",
    "aegis-auto-clean-shutdown.service",
)

HOOK_NAME = "aegis-auto-terminal-hook"
HOOK_SOURCE = "packaging/systemd/system-shutdown/" + HOOK_NAME


def function(source: str, name: str) -> str:
    matches = re.findall(r"^" + re.escape(name) + r"\(\) \{\n(.*?)^\}", source,
                         re.M | re.S)
    assert len(matches) == 1, f"exact {name} function required"
    return name + "() {\n" + matches[0] + "}\n"


def roster(body: str, kind: str) -> tuple[str, ...]:
    match = re.search(r"  for " + kind + r" in \\\n(.*?)^    ([^\n]+); do$", body,
                      re.M | re.S)
    assert match is not None, f"exact {kind} roster absent"
    names = []
    for line in [*match[1].splitlines(), match[2]]:
        entry = line.strip().removesuffix("\\").strip()
        grammar = r"[A-Za-z0-9_.-]+" if kind == "module" else r"[A-Za-z0-9_.@-]+"
        assert re.fullmatch(grammar, entry), "invalid roster entry"
        names.append(entry)
    assert len(names) == len(set(names)), "duplicate roster entry"
    return tuple(names)


def run_copy(definition: str, source: Path, target: Path) -> subprocess.CompletedProcess:
    (target / "helpers/lib").mkdir(parents=True)
    shell = r'''set -euo pipefail
ROOT="$1"
SYSTEMD_DIR="$2"
helper_dir="$3"
COPY_LOG="$4"
ensure_dir() { /bin/mkdir -p "$1"; }
install_copy_file() {
  printf '%s\n' "$1" >> "$COPY_LOG"
  [[ -f "$1" && ! -L "$1" ]] || return 1
  /usr/bin/install -m "$3" "$1" "$2"
}
systemctl() { return 99; }
''' + definition + '\ninstall_client_auto_native_assets "$helper_dir"\n'
    return subprocess.run(["/bin/bash", "-c", shell, "copy-fixture", str(source),
                           str(target / "units"), str(target / "helpers"),
                           str(target / "copy.log")],
                          stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, timeout=10, check=False)


def main() -> None:
    source = (ROOT / "install.sh").read_text()
    definition = function(source, "install_client_auto_native_assets")
    wide = function(source, "install_client_wide_helpers")
    role = function(source, "install_root_auto_native_role")
    ordinary = function(source, "install_client_role")
    assert roster(definition, "module") == MODULES
    assert roster(definition, "unit") == UNITS
    assert wide.count('install_client_auto_native_assets "${helper_dir}" || return 1') == 1
    assert 'if [[ "$(detect_os_kind)" == linux ]]; then' in wide
    assert 'install_root_auto_native_role || return 1' in wide
    assert 'if [[ "${AUTO_NATIVE_ROLE}" == admin ]]; then' in wide
    caller = [line for line in ordinary.splitlines()
              if 'install_client_wide_helpers "${helper_dir}"' in line]
    assert caller == ['  install_client_wide_helpers "${helper_dir}" || return 1'], \
        "ordinary client caller must propagate passive copy refusal"
    caller_probe = ('set -euo pipefail\nhelper_dir=fixture\n'
                    'install_client_wide_helpers() { return 47; }\n'
                    'ordinary_client_caller() {\n' + caller[0] +
                    '\n  printf unexpected-success\\n\n}\nordinary_client_caller\n')
    refused = subprocess.run(["/bin/bash", "-c", caller_probe],
                             stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, timeout=3, check=False)
    assert refused.returncode != 0 and b"unexpected-success" not in refused.stdout, \
        "ordinary client caller continued after missing AUTO asset"
    commands = "\n".join(line.strip() for line in definition.splitlines()
                         if line.strip() and not line.strip().startswith("#"))
    for forbidden in ("systemctl", "provision", "enable", " start ", "aegis-device-egress-guard.service"):
        assert forbidden not in commands, "passive installer gained activation"
    assert '"${helper_dir}/lib/${module}" 0500 || return 1' in definition
    assert '"${SYSTEMD_DIR}/${unit}" 0644 || return 1' in definition
    assert '"${helper_dir}/aegis-device-egress-guard.sh" 0755 || return 1' in definition
    with tempfile.TemporaryDirectory(prefix="aegis-auto-install-assets-") as temp:
        fixture = Path(temp)
        role_shell = ('set -euo pipefail\nROOT="$1"\nSOURCE_LAYOUT="$2"\n'
                      + role + '\ninstall_root_auto_native_role\n'
                      'printf "%s\\n" "$AUTO_NATIVE_ROLE"\n')
        role_root = fixture / "role"
        role_root.mkdir()
        for schema, expected in (("aegis_release_bundle_manifest_v2", "admin"),
                                 ("aegis_client_release_bundle_manifest_v3", "public"),
                                 ("unknown", None)):
            (role_root / "bundle.manifest.json").write_text(json.dumps({"schema": schema}))
            result = subprocess.run(["/bin/bash", "-c", role_shell, "role-fixture",
                                     str(role_root), "0"], stdin=subprocess.DEVNULL,
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                    timeout=3, check=False)
            if expected is None:
                assert result.returncode != 0, "unknown packaged role admitted"
            else:
                assert result.returncode == 0 and result.stdout == (expected + "\n").encode(), \
                    "packaged role admission changed"
        source_role = subprocess.run(["/bin/bash", "-c", role_shell, "role-fixture",
                                      str(role_root), "1"], stdin=subprocess.DEVNULL,
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                     timeout=3, check=False)
        assert source_role.returncode == 0 and source_role.stdout == b"admin\n"
        shadow = fixture / "source"
        for name in MODULES:
            dest = shadow / "scripts/lib" / name
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / "scripts/lib" / name, dest)
        for name in UNITS:
            dest = shadow / "packaging/systemd" / name
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / "packaging/systemd" / name, dest)
        dest = shadow / "scripts/aegis-device-egress-guard.sh"
        shutil.copyfile(ROOT / "scripts/aegis-device-egress-guard.sh", dest)
        dest = shadow / HOOK_SOURCE
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / HOOK_SOURCE, dest)
        installed = fixture / "installed"
        result = run_copy(definition, shadow, installed)
        assert result.returncode == 0, result.stderr.decode(errors="replace")
        for name in MODULES:
            path = installed / "helpers/lib" / name
            assert path.read_bytes() == (ROOT / "scripts/lib" / name).read_bytes()
            assert stat.S_IMODE(path.stat().st_mode) == 0o500
        for name in UNITS:
            path = installed / "units" / name
            assert path.read_bytes() == (ROOT / "packaging/systemd" / name).read_bytes()
            assert stat.S_IMODE(path.stat().st_mode) == 0o644
        path = installed / "helpers/aegis-device-egress-guard.sh"
        assert path.read_bytes() == (ROOT / "scripts/aegis-device-egress-guard.sh").read_bytes()
        assert stat.S_IMODE(path.stat().st_mode) == 0o755
        hook = installed / "helpers/lib" / HOOK_NAME
        assert hook.read_bytes() == (ROOT / HOOK_SOURCE).read_bytes()
        assert stat.S_IMODE(hook.stat().st_mode) == 0o500
        assert {path.name for path in (installed / "helpers/lib").iterdir()} == set(MODULES) | {HOOK_NAME}
        assert {path.name for path in (installed / "units").iterdir()} == set(UNITS)
        assert not (installed / "units/aegis-device-egress-guard.service").exists()
        expected = ["scripts/aegis-device-egress-guard.sh",
                    *("scripts/lib/" + name for name in MODULES),
                    HOOK_SOURCE, *("packaging/systemd/" + name for name in UNITS)]
        attempts = [str(shadow / name) for name in expected]
        assert (installed / "copy.log").read_text().splitlines() == attempts
        missing_sources = ["scripts/lib/aegis_auto_guardian.py",
                           *("scripts/lib/" + name for name in MODULES if name in {
                               "aegis_auto_terminal_witness.py",
                               "aegis_auto_terminal_boot_store.py",
                               "aegis_auto_terminal_register.py",
                               "aegis_auto_boot_transition.py"}),
                           HOOK_SOURCE, *("packaging/systemd/" + name for name in UNITS
                                          if name.startswith("aegis-auto-terminal-"))]
        for index, missing in enumerate(missing_sources):
            path = shadow / missing
            raw = path.read_bytes()
            path.unlink()
            target = fixture / f"missing-source-{index}"
            try:
                failed = run_copy(definition, shadow, target)
                assert failed.returncode != 0, missing + " did not refuse"
                stop = attempts.index(str(path)) + 1
                assert (target / "copy.log").read_text().splitlines() == attempts[:stop], \
                    missing + " failed before the intended copy or continued afterward"
            finally:
                path.write_bytes(raw)
    print("PASS passive AUTO install: admin/public/source roles, exact21 modules+hook/0500, exact16 units/0644, guard/0755, ten targeted missing-source refusals and caller refusal")


if __name__ == "__main__":
    main()
