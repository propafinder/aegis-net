#!/usr/bin/env bash
# Actual installer functions with only private temporary paths and purge stubs.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
python3 - "${ROOT}" <<'PY'
import os
import hashlib
import importlib.util
import json
import stat
import shutil
import re
import subprocess
import sys
import tempfile
from pathlib import Path

root = Path(sys.argv[1])
source = (root / "install.sh").read_text()
def actual_server_reader():
    selected = os.environ.get("AEGIS_TEST_SECRET_READER")
    if selected:
        reader = Path(selected).resolve(strict=True)
    else:
        assert all(os.environ.get(key) for key in ("RUNNER_TEMP", "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT", "GITHUB_SHA")), "INVALID actual prebuilt server required"
        spec = importlib.util.spec_from_file_location("local_copy_mode_fixture", root / "scripts/test-installer-secret-local-copy-mode-contract.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        prebuild = Path(os.environ["RUNNER_TEMP"]) / f"installer-source-prebuild-{os.environ['GITHUB_RUN_ID']}-{os.environ['GITHUB_RUN_ATTEMPT']}"
        client = module.retained_prebuild_client(prebuild, root, os.environ["GITHUB_SHA"])
        bundle = client.parent.parent
        manifest = json.loads((bundle / "bundle.manifest.json").read_text())
        entry = manifest["binaries"]["aegis-server"]
        assert entry["path"] == "bin/aegis-server" and entry["path"] in manifest["files"], "INVALID server manifest role"
        reader = bundle / entry["path"]
        assert stat.S_ISREG(reader.lstat().st_mode) and module.digest(reader) == entry["sha256"], "INVALID server manifest digest"
    assert reader.is_file() and os.access(reader, os.X_OK), "INVALID actual compiled server reader required"
    return reader


reader = actual_server_reader()


def function(name):
    match = re.search(r'^' + name + r'\(\) \{\n.*?^\}', source, re.M | re.S)
    assert match, name
    return match[0] + "\n"


actual = "".join(function(name) for name in (
    "apply_existing_install_choice", "handle_existing_install",
    "install_manifest_path_for_role", "install_atomic_write",
    "client_config_boundary_tree", "prepare_client_config_boundary",
    "install_client_role", "install_server_role",
))
stubs = '''
resolve_existing_install_choice() { printf '%s' "$CHOICE"; }
default_client_helper_dir() { printf '%s/helpers' "$PREFIX"; }
host_from_address() { printf fixture.invalid; }
current_user_name() { printf fixture-user; }
current_group_name() { printf fixture-group; }
mutation_checkpoint() { printf overwrite >> "$MUTATION"; exit 98; }
deactivate_existing_wide_boot_units() { mutation_checkpoint; }
install_binary() {
  if [[ "${4:-}" == "preflight" ]]; then
    printf preflight >> "$PREFLIGHT"
    return 0
  fi
  mutation_checkpoint
}
resolve_downloaded_bundle() { printf download >> "$DOWNLOAD"; exit 97; }
command_not_found_handle() { printf 'unexpected fixture command: %s\n' "$1" >&2; exit 96; }
trap 'printf "%s" "$FORCE" > "$FORCE_RESULT"' EXIT
'''
purge_stub = '''#!/bin/bash
printf '%s\n' "$1" "$2" "$AEGIS_PURGE_PRESERVE_PATH" "$AEGIS_PURGE_TMPDIR" > "$PURGE_LOG"
exit "$PURGE_STATUS"
'''

with tempfile.TemporaryDirectory(prefix="aegis-reinstall-failclosed-") as temp:
    work = Path(temp)
    package = work / "package"
    (package / "scripts").mkdir(parents=True)
    (package / "bin").mkdir(mode=0o700)
    reader_digest = hashlib.sha256(reader.read_bytes()).hexdigest()
    reader_copy = package / "bin/aegis-server"
    shutil.copyfile(reader, reader_copy)
    reader_copy.chmod(0o700)
    assert reader_digest == hashlib.sha256(reader_copy.read_bytes()).hexdigest() == hashlib.sha256(reader.read_bytes()).hexdigest(), "INVALID reader copy custody"
    version = subprocess.run([str(reader_copy), "installer-secret", "version"],
                             capture_output=True, text=True, timeout=5)
    assert version.returncode == 0 and version.stdout.strip() == "installer-secret-v1", "INVALID actual reader protocol"
    bundle = work / "validated bundle"
    bundle.mkdir()
    (bundle / "aegis-client.toml").write_text('mode = "relay"\n')
    (bundle / "ca.pem").write_text("fixture CA\n")
    config = work / "config"
    config.mkdir()
    sentinel = config / "aegis.toml"
    sentinel.write_text("old installation sentinel\n")
    helper = package / "scripts/purge-installed-aegis.sh"
    purge_log, mutation = work / "purge.log", work / "mutation"
    preflight, download, force_result = work / "preflight", work / "download", work / "force"
    env = {**os.environ, "ROOT": str(package), "TMPDIR": str(work), "PREFIX": str(work / "prefix"),
           "CONFIG_DIR": str(config), "STATE_DIR": str(work / "state"), "LOG_DIR": str(work / "logs"),
           "SYSTEMD_DIR": str(work / "units"), "ENV_DIR": str(work / "env"), "BUNDLE_PATH": str(bundle),
           "BUNDLE_URL": "", "BUNDLE_URL_FILE": "", "AUTH_TOKEN": "fixture", "AUTH_TOKEN_FILE": "",
           "SOURCE_LAYOUT": "0", "RELAY_ADDRESS": "fixture.invalid:443",
           "DEVICE_ID": "", "DEVICE_CERTIFICATE": "", "DEVICE_IDENTITY_DIR": "", "DEVICE_BUNDLE": "0",
           "STAGE_AUTO_DEVICE_GUARD": "0", "STAGE_AUTO_OWNER_RECEIPT": "",
           "PRODUCT_MODE": "socks-only",
           "PREFLIGHT_CLIENT_BINARY": "/fixture/abi-preflight-only-client",
           "AEGIS_INSTALL_TEST_FORCE_STATE_MANIFEST": "1",
           "SERVER_NAME": "fixture.invalid", "LISTEN_ADDR_EXPLICIT": "1", "LISTEN_ADDR": "127.0.0.1:443",
           "BUNDLE_OUT": str(work / "server-bundle"), "BUNDLE_ARCHIVE_OUT": str(work / "server-bundle.tar.gz"),
           "PURGE_LOG": str(purge_log), "MUTATION": str(mutation), "PREFLIGHT": str(preflight),
           "DOWNLOAD": str(download), "FORCE_RESULT": str(force_result)}
    entries = {
        "apply": 'apply_existing_install_choice client "$CHOICE" "$BUNDLE_PATH"',
        "handle": 'handle_existing_install server "$CONFIG_DIR"',
        "client": "install_client_role",
        "server": "install_server_role",
    }

    def run(entry, mode, initial_force="0", conditional=False):
        for path in (purge_log, mutation, preflight, download, force_result, helper):
            path.unlink(missing_ok=True)
        if mode != "missing":
            helper.write_text(purge_stub)
            helper.chmod(0o644 if mode == "not-executable" else 0o755)
        call = entries[entry]
        if conditional:
            call = 'if ' + call + '; then status=0; else status=$?; fi\nexit "$status"'
        else:
            call += '\nstatus=$?\nexit "$status"'
        result = subprocess.run(
            ["/bin/bash", "-c", ("set -e\n" if conditional else "set +e\n") + "set -u\n" + actual + stubs + call],
            env={**env, "FORCE": initial_force, "CHOICE": "cancel" if mode == "cancel" else "reinstall",
                 "PURGE_STATUS": "37" if mode == "failed" else "0"},
            capture_output=True, text=True, timeout=5,
        )
        expected = 37 if mode == "failed" else 1 if mode in ("missing", "not-executable") else 0
        if mode == "success" and entry in ("client", "server"):
            expected = 98  # First post-purge mutation is a terminating stub.
        assert result.returncode == expected, (entry, mode, result.returncode, result.stderr)
        assert force_result.read_text() == ("1" if mode == "success" else initial_force)
        assert mutation.exists() == (mode == "success" and entry in ("client", "server"))
        assert not download.exists(), "cancel consumed one-time input or local bundle unexpectedly downloaded"
        assert sentinel.read_text() == "old installation sentinel\n"
        assert (bundle / "aegis-client.toml").is_file() and (bundle / "ca.pem").is_file()
        if mode in ("failed", "success"):
            role = "server" if entry in ("server", "handle") else "client"
            preserve = "" if entry in ("server", "handle") else str(bundle.resolve() if entry == "client" else bundle)
            assert purge_log.read_text().splitlines() == [role, "--force", preserve, str(work)], (entry, mode, purge_log.read_text())
        else:
            assert not purge_log.exists(), "missing helper or cancel ran purge"
        if mode == "failed":
            assert "Partial purge changes are not rolled back" in result.stderr
        if mode == "cancel":
            assert not preflight.exists(), "cancel reached binary preflight"

    for entry in entries:
        for conditional in (False, True):
            for mode in ("failed", "missing", "not-executable", "success", "cancel"):
                run(entry, mode, conditional=conditional)
            # Explicit --force must not bypass a failed/missing reinstall purge.
            for mode in ("failed", "missing"):
                run(entry, mode, initial_force="1", conditional=conditional)

    for path in (purge_log, mutation, preflight, download):
        path.unlink(missing_ok=True)
    result = subprocess.run(
        ["/bin/bash", "-c", "set -eu\n" + actual + stubs + "install_client_role"],
        env={**env, "FORCE": "1", "CHOICE": "reinstall", "PURGE_STATUS": "0",
             "AUTO_PROFILE": "1", "BUNDLE_PATH": "", "LOG_DIR": "/var/log/aegis-client"},
        capture_output=True, text=True, timeout=5,
    )
    assert result.returncode == 1, result.stderr
    assert 'fresh automatic reinstall requires --bundle or --bundle-url-file' in result.stderr
    assert not purge_log.exists() and not mutation.exists()
    assert sentinel.read_text() == "old installation sentinel\n"
    print("PASS: actual apply/handle/client/server fail closed without errexit; failed/missing purge stops overwrite; successful FORCE/preserve env and cancel retained")
PY
