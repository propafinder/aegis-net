#!/usr/bin/env python3
"""Inert private helper inventory/copy boundary; never run helper bodies/builders."""
import argparse
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tempfile

HELPER = "setup-wide-linux-nfqueue.sh"
CONTROLS = ("setup-wide-linux-redirect.sh", "setup-wide-linux-tproxy.sh")


def inventory(source, name):
    matches = re.findall(r"^" + name + r"=\(\n(.*?)^\)\s*$", source, re.M | re.S)
    assert len(matches) == 1, "array declaration boundary"
    names = []
    for line in matches[0].splitlines():
        match = re.fullmatch(r'  "([A-Za-z0-9_./-]+)"', line)
        assert match is not None, "literal inventory only"
        name = match[1]
        assert not name.startswith("/") and ".." not in name.split("/"), "relative inventory only"
        names.append(name)
    assert len(names) == len(set(names)), "duplicate helper inventory"
    return names


def copy_loop(source, array, destination):
    # Only inspect declarations/array consumer structure, never execute builders.
    prefix = 'for helper_script in "${' + array + '[@]}"; do'
    bodies = re.findall(re.escape(prefix) + r"\n(.*?)^done$", source, re.M | re.S)
    dest = destination + '/${helper_script}'
    assert any('cp "${ROOT}/scripts/${helper_script}" "' + dest + '"' in body for body in bodies), "array copy consumer absent"
    assert any('chmod 0755 "' + dest + '"' in body for body in bodies), "array executable mode consumer absent"


def install_function(source):
    matches = re.findall(r"^install_client_wide_helpers\(\) \{\n(.*?)^\}$", source, re.M | re.S)
    assert len(matches) == 1, "installer function boundary"
    body = matches[0]
    # Full-line grammar rejects trailing shell commands before any spawn.
    path = r"[A-Za-z0-9_/-]+(?:\.[A-Za-z0-9_-]+)*"
    patterns = (
        r'local helper_dir="\$1"',
        r'ensure_dir "\$\{helper_dir\}(?:/lib)?" \|\| return 1',
        r'install_copy_file "\$\{ROOT\}/scripts/' + path + r'" \\',
        r'install_copy_file "\$\{ROOT\}/scripts/' + path + r'" "\$\{helper_dir\}/' + path + r'" (?:0644|0755) \|\| return 1',
        r'"\$\{helper_dir\}/' + path + r'" (?:0644|0755) \|\| return 1',
        r'if \[\[ -f "\$\{ROOT\}/scripts/' + path + r'" \]\]; then',
        r'if \[\[ "\$\(detect_os_kind\)" == linux \]\]; then',
        r'install_root_auto_native_role \|\| return 1',
        r'if \[\[ "\$\{AUTO_NATIVE_ROLE\}" == admin \]\]; then',
        r'install_client_auto_native_assets "\$\{helper_dir\}" \|\| return 1',
        r'fi',
    )
    pending_copy = False
    for line in body.splitlines():
        text = line.strip()
        if pending_copy:
            assert re.fullmatch(patterns[4], text), "copy destination must immediately follow source"
            assert ".." not in text, "no parent path in copy function"
            pending_copy = False
            continue
        if not text or text.startswith("#"):
            continue
        assert ".." not in text, "no parent path in copy function"
        assert not re.fullmatch(patterns[4], text), "standalone copy destination refused"
        assert any(re.fullmatch(pattern, text) for index, pattern in enumerate(patterns) if index != 4), "unexpected installer function statement"
        pending_copy = re.fullmatch(patterns[2], text) is not None
    assert not pending_copy, "unterminated copy source refused"
    return "install_client_wide_helpers() {\n" + body + "}\n"


def materialize(root, names, destination):
    for name in (HELPER, *CONTROLS):
        if name not in names:
            continue
        source = root / "scripts" / name
        assert source.is_file(), "listed source missing"
        target = destination / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
        target.chmod(0o755)


def check_copy(root, destination):
    for name in (HELPER, *CONTROLS):
        target = destination / name
        assert target.is_file(), "required helper missing from copy boundary"
        assert target.read_bytes() == (root / "scripts" / name).read_bytes(), "helper bytes changed"
        assert stat.S_IMODE(target.stat().st_mode) == 0o755, "helper mode changed"


def invoke_install(function, fake_root, destination, fail_nfqueue=False):
    # Only the extracted copy function is sourced into this shell. File-copy
    # commands are mocked local operations in a freshly owned temporary tree.
    harness = r'''set -euo pipefail
ROOT="$1"
target="$2"
fail_nfqueue="$3"
SOURCE_LAYOUT=0
ensure_dir() { /bin/mkdir -p "$1"; }
install_copy_file() {
  if [[ "$fail_nfqueue" == 1 && "$1" == */setup-wide-linux-nfqueue.sh ]]; then return 1; fi
  [[ -f "$1" ]] || return 1
  /bin/cp "$1" "$2" || return 1
  /bin/chmod "$3" "$2" || return 1
}
detect_os_kind() { printf 'darwin\n'; }
install_root_auto_native_role() { AUTO_NATIVE_ROLE=public; }
''' + function + '\ninstall_client_wide_helpers "$target"\n'
    return subprocess.run(["/bin/bash", "-c", harness, "inert-copy", str(fake_root), str(destination), "1" if fail_nfqueue else "0"], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=8, check=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline-preimages", type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    paths = ("scripts/build-release-bundle.sh", "scripts/build-package-root.sh", "install.sh")
    sources = {}
    for relative in paths:
        file = root / relative if args.baseline_preimages is None else args.baseline_preimages / ("preimage-" + relative.replace("/", "__"))
        sources[relative] = file.read_text()
    release = sources[paths[0]]
    package = sources[paths[1]]
    declarations = (inventory(release, "HELPER_SCRIPTS"), inventory(package, "HELPER_SCRIPTS"), inventory(package, "WIDE_HELPER_SCRIPTS"))
    copy_loop(release, "HELPER_SCRIPTS", "${BUNDLE_DIR}/scripts")
    copy_loop(package, "HELPER_SCRIPTS", "${ROOTFS_DIR}/usr/share/aegis/scripts")
    copy_loop(package, "WIDE_HELPER_SCRIPTS", "${ROOTFS_DIR}/usr/local/lib/aegis/helpers")
    function = install_function(sources[paths[2]])
    # Pure parser negatives are refused before any subprocess is started.
    safe = 'ensure_dir "${helper_dir}" || return 1'
    for bad in (safe + '; /bin/false', safe + ' | /bin/false', safe + ' & /bin/false',
                'ensure_dir "$(/bin/false)" || return 1', 'fi; /bin/false',
                '"${helper_dir}/setup-wide-linux-nfqueue.sh" 0755 || return 1',
                'install_copy_file "${ROOT}/scripts/setup-wide-linux-nfqueue.sh" \\',
                'install_copy_file "${ROOT}/scripts/setup-wide-linux-nfqueue.sh" \\\n# interrupted',
                'install_copy_file "${ROOT}/scripts/setup-wide-linux-nfqueue.sh" \\\n\n"${helper_dir}/setup-wide-linux-nfqueue.sh" 0755 || return 1',
                'install_copy_file "${ROOT}/scripts/setup-wide-linux-nfqueue.sh" \\\n' + safe):
        refused = False
        try:
            install_function("install_client_wide_helpers() {\n  " + bad + "\n}\n")
        except AssertionError:
            refused = True
        assert refused, "unsafe parser statement accepted before spawn"
    with tempfile.TemporaryDirectory(prefix="aegis-private-helper-inert-") as temp:
        fixture = Path(temp)
        for names, relative in zip(declarations, ("bundle/scripts", "rootfs/usr/share/aegis/scripts", "rootfs/usr/local/lib/aegis/helpers")):
            target = fixture / relative
            materialize(root, names, target)
            check_copy(root, target)
            assert names.count(HELPER) == 1, "private helper inventory missing or repeated"
        fake_root = fixture / "source"
        copied = set(re.findall(r'\$\{ROOT\}/scripts/([A-Za-z0-9_./-]+)', function))
        for name in copied:
            target = fake_root / "scripts" / name
            target.parent.mkdir(parents=True, exist_ok=True)
            if name in (HELPER, *CONTROLS):
                shutil.copyfile(root / "scripts" / name, target)
            else:
                target.write_bytes(b"# inert copy placeholder\n")
        installed = fixture / "installed/helpers"
        result = invoke_install(function, fake_root, installed)
        assert result.returncode == 0, "extracted local installer copy failed"
        check_copy(root, installed)
        assert function.count('install_copy_file "${ROOT}/scripts/' + HELPER + '"') == 1, "installer inventory missing or repeated"
        # Present private helper copy failure must propagate; no runtime
        # prerequisites are inferred from this mocked copy refusal.
        result = invoke_install(function, fake_root, fixture / "failed-copy/helpers", fail_nfqueue=True)
        assert result.returncode != 0, "present private helper copy failure was ignored"
        # The same installer supports the public kit, which deliberately does
        # not distribute this experimental helper. Its absence is not failure.
        (fake_root / "scripts" / HELPER).unlink()
        public_installed = fixture / "public-installed/helpers"
        result = invoke_install(function, fake_root, public_installed)
        assert result.returncode == 0, "public helper absence broke ordinary installation copy"
        assert not (public_installed / HELPER).exists(), "private helper fabricated in public fixture"
        for name in CONTROLS:
            target = public_installed / name
            assert target.read_bytes() == (root / "scripts" / name).read_bytes(), "public ordinary helper bytes changed"
            assert stat.S_IMODE(target.stat().st_mode) == 0o755, "public ordinary helper mode changed"
        (fake_root / "scripts" / CONTROLS[0]).unlink()
        result = invoke_install(function, fake_root, fixture / "missing-required/helpers")
        assert result.returncode != 0, "missing ordinary required helper did not reject copy"
    print("PASS: closed extraction, private inventory/bytes/0755, public absence/controls, copy refusals")


if __name__ == "__main__":
    main()
