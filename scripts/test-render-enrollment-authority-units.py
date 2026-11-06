#!/usr/bin/env python3
"""Inert contract checks; no systemd, keys, registry, network or host mutation."""

import importlib.util
import subprocess
import sys
import tempfile
from pathlib import Path


HERE = Path(__file__).resolve().parent
TOOL = HERE / "render-enrollment-authority-units.py"
spec = importlib.util.spec_from_file_location("render_units", TOOL)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
TEMPLATES = HERE.parent / "packaging/systemd"
SOURCE_COMMIT = subprocess.check_output(
    ["git", "-C", str(HERE.parent), "rev-parse", "HEAD"],
    text=True,
    timeout=5,
).strip()


def run(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(TOOL), *args],
        text=True,
        capture_output=True,
        check=False,
        timeout=5,
    )


with tempfile.TemporaryDirectory(prefix="aegis-unit-render-test-") as directory:
    root = Path(directory)
    staged = root / "staged"
    result = run("--source-commit", SOURCE_COMMIT, "--output-dir", str(staged))
    assert result.returncode == 0, result.stderr
    assert "PASS: three units" in result.stdout
    assert (staged.stat().st_mode & 0o777) == 0o700
    expected = module.expected_units(TEMPLATES, SOURCE_COMMIT)
    for name, body in expected.items():
        original = (TEMPLATES / name).read_bytes()
        assert body == original.replace(
            module.LEGACY,
            b"ExecStart=" + module.release_binary(SOURCE_COMMIT) + b" ",
        )
        assert (staged / name).read_bytes() == body
        assert ((staged / name).stat().st_mode & 0o777) == 0o600
    assert b"OnSuccess=aegis-enrollment-policy-publish.service" in expected[
        "aegis-enrollment-policy-stage.service"
    ]
    assert b"StandardOutput=file:/var/lib/aegis-device-policy-transfer/snapshot.json" in expected[
        "aegis-enrollment-policy-stage.service"
    ]
    assert b"InaccessiblePaths=/var/lib/aegis-enrollment/private" in expected[
        "aegis-enrollment-policy-stage.service"
    ]
    assert run("--source-commit", SOURCE_COMMIT, "--check-dir", str(staged)).returncode == 0
    assert run("--source-commit", SOURCE_COMMIT, "--output-dir", str(staged)).returncode == 1

    dropin = staged / "aegis-enrollment-authority.service.d"
    dropin.mkdir()
    assert run("--source-commit", SOURCE_COMMIT, "--check-dir", str(staged)).returncode == 1
    dropin.rmdir()

    mixed = staged / "aegis-enrollment-policy-stage.service"
    mixed.write_bytes(mixed.read_bytes().replace(SOURCE_COMMIT.encode(), b"4d0a8fd2"))
    assert run("--source-commit", SOURCE_COMMIT, "--check-dir", str(staged)).returncode == 1
    mixed.write_bytes(expected[mixed.name])

    legacy = staged / "aegis-enrollment-authority.service"
    legacy.write_bytes(legacy.read_bytes().replace(module.release_binary(SOURCE_COMMIT), b"/usr/local/bin/aegis-server"))
    assert run("--source-commit", SOURCE_COMMIT, "--check-dir", str(staged)).returncode == 1
    legacy.write_bytes(expected[legacy.name])

    legacy.unlink()
    legacy.symlink_to(TEMPLATES / legacy.name)
    assert run("--source-commit", SOURCE_COMMIT, "--check-dir", str(staged)).returncode == 1
    legacy.unlink()
    legacy.write_bytes(expected[legacy.name])

    assert run("--source-commit", "bad", "--check-dir", str(staged)).returncode == 1
    assert run("--source-commit", "0" * 40, "--check-dir", str(staged)).returncode == 1
    assert run("--source-commit", "4d0a8fd216dd0c5897d60831520bcb08dfa7d2ff", "--check-dir", str(staged)).returncode == 1

    altered = root / "altered" / "packaging" / "systemd"
    altered.mkdir(parents=True)
    for name in module.UNITS:
        (altered / name).write_bytes((TEMPLATES / name).read_bytes())
    changed = altered / module.UNITS[0]
    changed.write_bytes(changed.read_bytes() + b"# changed checkout\n")
    try:
        module.expected_units(altered, SOURCE_COMMIT)
    except ValueError as exc:
        assert "template differs from source commit" in str(exc)
    else:
        raise AssertionError("changed template was accepted for source commit")

print("PASS: render, exact check, byte-preserved sandbox, exclusive staging, drop-in/mixed/legacy/symlink/source, unknown-commit and modified-template refusals (11/11)")
