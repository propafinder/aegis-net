#!/usr/bin/env bash
# Signed mirror pairs and one-time archive staging, isolated from host install.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
python3 - "${ROOT}" <<'PY'
import hashlib
import io
import importlib.util
import shutil
import json
import os
import re
import subprocess
import sys
import tarfile
import tempfile
import time
from pathlib import Path

root = Path(sys.argv[1])
bootstrap = (root / "bootstrap-install.sh").read_text()
installer = (root / "install.sh").read_text()


def actual_client():
    selected = os.environ.get("AEGIS_TEST_SECRET_CLIENT")
    if selected:
        path = Path(selected).resolve(strict=True)
    else:
        assert all(os.environ.get(key) for key in ("RUNNER_TEMP", "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT", "GITHUB_SHA")), "INVALID actual prebuilt client required"
        spec = importlib.util.spec_from_file_location("local_copy_mode_fixture", root / "scripts/test-installer-secret-local-copy-mode-contract.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        prebuild = Path(os.environ["RUNNER_TEMP"]) / f"installer-source-prebuild-{os.environ['GITHUB_RUN_ID']}-{os.environ['GITHUB_RUN_ATTEMPT']}"
        path = module.retained_prebuild_client(prebuild, root, os.environ["GITHUB_SHA"])
    assert path.is_file() and os.access(path, os.X_OK), "INVALID real client required"
    return path


def function(source, name):
    match = re.search(r'^' + name + r'\(\) \{\n.*?^\}', source, re.M | re.S)
    assert match, name
    return match[0] + "\n"


def command(args, **kwargs):
    return subprocess.run(args, capture_output=True, text=True, timeout=15, **kwargs)


with tempfile.TemporaryDirectory(prefix="aegis-acquisition-contract-") as temp:
    work = Path(temp)
    work.chmod(0o700)
    client_input = actual_client()
    client = work / "aegis-client"
    client_digest = hashlib.sha256(client_input.read_bytes()).hexdigest()
    shutil.copyfile(client_input, client)
    client.chmod(0o700)
    assert client_digest == hashlib.sha256(client.read_bytes()).hexdigest() == hashlib.sha256(client_input.read_bytes()).hexdigest(), "INVALID real client copy custody"
    version = command([str(client), "profile", "installer-secret", "version"])
    assert version.returncode == 0 and version.stdout.strip() == "installer-secret-v1", "INVALID private input reader protocol"
    private_inputs = work / "private-inputs"
    private_inputs.mkdir(mode=0o700)

    def private_url(path, source):
        with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as output:
            output.write(source.as_uri().encode())
        path.chmod(0o600)
        return str(path)
    fixture_home = work / 'home'
    fixture_home.mkdir(mode=0o700)
    # Only relocate authoritative roots in this fixture copy. Keep signature,
    # freshness and persisted-floor functions intact, including root CI runs.
    bootstrap = bootstrap.replace('/var/lib/aegis-install/releases', str(work / 'root-release-floor')).replace(
        '/Library/Application Support/Aegis/Install/releases', str(work / 'root-release-floor'))
    key, public = work / "key.pem", work / "public.pem"
    for args in (
        ["openssl", "genpkey", "-algorithm", "ed25519", "-out", str(key)],
        ["openssl", "pkey", "-in", str(key), "-pubout", "-out", str(public)],
    ):
        result = command(args)
        assert result.returncode == 0, result.stderr

    policy_manifest = {'version': '0.0.0', 'channel': 'rc', 'prerelease': True,
        'release_policy': {'schema': 'aegis_release_policy_v1',
            'authority': 'github:fixture/aegis:.github/workflows/release.yml', 'sequence': 1,
            'tag': 'v0.0.0-rc.1', 'issued_at_unix': int(time.time()) - 10,
            'expires_at_unix': int(time.time()) + 3600}}
    def signed(name, content=None):
        path = work / name
        if content is None:
            content = json.dumps(policy_manifest).encode()
        path.write_bytes(content)
        result = command(["openssl", "pkeyutl", "-sign", "-inkey", str(key), "-rawin", "-in", str(path), "-out", str(path) + ".sig"])
        assert result.returncode == 0, result.stderr
        return path

    good = signed("good.json")
    no_policy = signed('no-policy.json', b'{"version":"0.0.0","channel":"rc","prerelease":true}')
    expired_manifest = json.loads(json.dumps(policy_manifest))
    expired_manifest['release_policy'].update(issued_at_unix=int(time.time()) - 3600, expires_at_unix=int(time.time()) - 60)
    expired = signed('expired.json', json.dumps(expired_manifest).encode())
    wrong = signed("wrong.json")
    wrong.write_bytes(b'{"fixture":"changed after signing"}\n')
    missing_signature = work / "missing-signature.json"
    missing_signature.write_bytes(good.read_bytes())
    signature_only = work / "signature-only.json"
    Path(str(signature_only) + ".sig").write_bytes(Path(str(good) + ".sig").read_bytes())
    empty = work / "empty.json"
    empty.write_bytes(b"")
    destination = work / "selected.json"
    helpers = "".join(function(bootstrap, name) for name in (
        "verify_manifest_signature", "validate_release_policy", "release_floor_run",
        "download_url", "download_url_with_fallback",
    ))

    def fallback(paths, expected, unsigned="0"):
        destination.write_bytes(b"stale manifest")
        Path(str(destination) + ".sig").write_bytes(b"stale signature")
        script = helpers + '''
AEGIS_MANIFEST_PUBKEY_PEM="$1"
destination="$2"
shift 2
download_url_with_fallback "$destination" "$@"
status=$?
printf '%s\\n' "$MANIFEST_URL_RESOLVED_BY_FALLBACK" "$MANIFEST_SIGNATURE_VERIFIED"
exit "$status"
'''
        result = command(["/bin/bash", "-c", script, "pair-contract", str(public), str(destination)] + [p.as_uri() for p in paths],
                         env={**os.environ, "AEGIS_ALLOW_UNSIGNED_MANIFEST": unsigned,
                              "HOME": str(fixture_home), "OS_KIND": "linux", "AEGIS_HOST_ARCH": "x86_64",
                              "ROLE": "client", "REQUIRE_RELEASE_POLICY": "1", "ALLOW_HISTORICAL_POLICY": "0",
                              "MINIMUM_RELEASE_SEQUENCE": "1",
                              "RELEASE_POLICY_AUTHORITY": "github:fixture/aegis:.github/workflows/release.yml"})
        if expected is None:
            assert result.returncode != 0, result.stderr
            assert not destination.exists() and not Path(str(destination) + ".sig").exists()
            assert result.stdout == "\n0\n", result.stdout
        else:
            assert result.returncode == 0, result.stderr
            assert result.stdout.splitlines()[0] == expected.as_uri(), result.stdout
            assert destination.read_bytes() == expected.read_bytes()
        assert not list(work.glob("selected.json.source.*")), "source staging leaked"
        assert not list(work.rglob("*.part.*")), "partial pair survived"

    fallback([good, work / "not-used"], good)
    fallback([work / "missing", empty, missing_signature, wrong, no_policy, expired, good], good)
    # Neither half may be borrowed from a different source or a prior call.
    fallback([missing_signature, signature_only], None)
    fallback([wrong, work / "missing"], None)
    fallback([missing_signature], None, unsigned="1")
    fallback([wrong], None, unsigned="1")
    fallback([no_policy, expired], None)
    print("PASS: complete signed pairs and real freshness/floor validation; invalid policy, unsigned legacy flag, cross-source/stale halves and exhausted sources refused")

    # Exercise the actual archive acquisition API, including its selected signed
    # digest. Keep this independent of the verifier's internal heredoc layout.
    digest_gate = function(bootstrap, "download_url") + function(bootstrap, "download_archive_with_fallback")
    archive = work / "release-archive.tar.gz"
    archive.write_bytes(b"complete but wrong release bytes")
    marker = work / "installed-marker"
    downloaded = work / "downloaded.tar.gz"
    archive_env = {**os.environ, "OFFLINE": "1", "ARCHIVE_PATH": str(downloaded),
                   "BUNDLE_SHA256": hashlib.sha256(b"expected release").hexdigest(),
                   "ARCHIVE_NAME": archive.name, "SOURCE_MANIFEST": (work / "fixture.json").as_uri(),
                   "MARKER": str(marker)}
    archive_script = 'set -e\n' + digest_gate + '''
download_archive_with_fallback "$ARCHIVE_PATH" "$BUNDLE_SHA256" "$ARCHIVE_NAME" "$SOURCE_MANIFEST"
printf touched > "$MARKER"
'''
    result = command(["/bin/bash", "-c", archive_script], env=archive_env)
    assert result.returncode != 0 and not marker.exists(), result.stderr
    assert "bundle checksum mismatch" in result.stderr
    assert not downloaded.exists(), "invalid archive survived acquisition"
    archive.write_bytes(b"expected release")
    result = command(["/bin/bash", "-c", archive_script], env=archive_env)
    assert result.returncode == 0 and marker.read_text() == "touched", result.stderr
    assert downloaded.read_bytes() == archive.read_bytes()

    bundle = work / "client.tar.gz"
    with tarfile.open(bundle, "w:gz") as output:
        for name, content in (("aegis-client.toml", b'mode = "relay"\n'), ("ca.pem", b"fixture-ca\n")):
            item = tarfile.TarInfo(name)
            item.size = len(content)
            output.addfile(item, io.BytesIO(content))
    truncated = work / "truncated.tar.gz"
    truncated.write_bytes(bundle.read_bytes()[:-8])
    garbage = work / "garbage.tar.gz"
    garbage.write_bytes(b"incomplete archive")
    blank = work / "blank.tar.gz"
    blank.write_bytes(b"")
    calls = work / "fetch-calls"
    binary_preflight = work / "binary-preflight"
    mutation = work / "mutations"
    sentinel = work / "installed-client"
    sentinel.write_bytes(b"old client and network must survive")
    prefix = '''set -euo pipefail
TEMP_PATHS=()
ensure_dir() { mkdir -p "$1"; }
cleanup() { for path in "${TEMP_PATHS[@]+${TEMP_PATHS[@]}}"; do [[ -z "$path" ]] || rm -rf -- "$path"; done; }
trap cleanup EXIT
'''
    real_download = function(installer, "download_url").replace("download_url()", "actual_download_url()", 1)
    staging = prefix + real_download + '''
download_url() { printf attempt >> "$CALLS"; actual_download_url "$@"; }
''' + function(installer, "resolve_downloaded_bundle")
    env = {**os.environ, "TMPDIR": str(work), "CALLS": str(calls), "BUNDLE_CACERT_PIN": "", "BUNDLE_INSECURE": "0", "PREFLIGHT_CLIENT_BINARY": str(client)}

    # Private URL admission uses the actual verified reader after read-only ABI
    # preflight. Failed acquisition still precedes every installation mutation,
    # purge and service helper. All target state is private temporary fixtures.
    role = function(installer, "install_client_role")
    role_stubs = '''
default_client_helper_dir() { printf '%s/helpers' "$PREFIX"; }
resolve_existing_install_choice() { printf reinstall; }
apply_existing_install_choice() { printf mutation >> "$MUTATION"; return 99; }
install_binary() {
  if [[ "${4:-}" == preflight ]]; then
    printf preflight >> "$BINARY_PREFLIGHT"
    PREFLIGHT_CLIENT_BINARY="$ACTUAL_FIXTURE_CLIENT"
    return 0
  fi
  printf mutation >> "$MUTATION"
  return 97
}
'''
    role_env = {**env, "PREFIX": str(work / "prefix"), "CONFIG_DIR": str(work / "config"),
                "STATE_DIR": str(work / "state"), "LOG_DIR": str(work / "logs"),
                "SYSTEMD_DIR": str(work / "units"), "ENV_DIR": str(work / "env"),
                "DEVICE_ID": "", "DEVICE_CERTIFICATE": "", "DEVICE_IDENTITY_DIR": "", "DEVICE_BUNDLE": "0",
                "PRODUCT_MODE": "", "BUNDLE_PATH": "", "BUNDLE_URL": "", "BUNDLE_URL_FILE": "", "FORCE": "1", "MUTATION": str(mutation),
                "BINARY_PREFLIGHT": str(binary_preflight), "ACTUAL_FIXTURE_CLIENT": str(client)}
    for index, fixture in enumerate((work / "unavailable", blank, truncated, garbage)):
        calls.write_text("")
        binary_preflight.unlink(missing_ok=True)
        record = private_url(private_inputs / f"source-{index}", fixture)
        result = command(["/bin/bash", "-c", staging + role_stubs + role + '\ninstall_client_role\n'],
                         env={**role_env, "BUNDLE_URL_FILE": record})
        assert result.returncode != 0, (fixture.name, result.stderr)
        assert calls.read_text() == "attempt", ("one-time owner invocation missing or repeated", result.stderr)
        assert binary_preflight.read_text() == "preflight" and not mutation.exists(), result.stderr
        assert not list(work.glob("aegis-installer-bundle.*")), "staging survived EXIT cleanup"
        assert sentinel.read_bytes() == b"old client and network must survive"
        assert "stage=bundle_acquisition" in result.stderr, result.stderr
        assert fixture.as_uri() not in result.stderr, "acquisition error exposed private source"
    calls.write_text("")
    record = private_url(private_inputs / "valid-bundle", bundle)
    result = command(["/bin/bash", "-c", staging + '\nresolved=""\nresolve_downloaded_bundle "$1" resolved\n[[ -s "$resolved/ca.pem" && -s "$resolved/aegis-client.toml" ]]\n', "staging-contract", record], env=env)
    assert result.returncode == 0 and calls.read_text() == "attempt", result.stderr
    assert not list(work.glob("aegis-installer-bundle.*"))
    print("PASS: signed archive digest remains fail-closed; missing/empty/truncated acquisition exits after read-only ABI and before purge; complete bundle staged once and cleaned")
PY
