#!/usr/bin/env bash
# Actual signed Mac manifest/digest stage, using only isolated local fixtures.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
python3 - "${ROOT}" <<'PY'
import hashlib
import io
import json
import os
import re
import subprocess
import sys
import tarfile
import tempfile
import time
from pathlib import Path

source = (Path(sys.argv[1]) / "bootstrap-install.sh").read_text()
deadline = time.monotonic() + 120


def command(args, **kwargs):
    remaining = deadline - time.monotonic()
    assert remaining > 0, "digest fixture budget exhausted"
    return subprocess.run(args, capture_output=True, text=True,
                          timeout=min(15, remaining), **kwargs)


def function(name):
    match = re.search(r'^' + name + r'\(\) \{\n.*?^\}', source, re.M | re.S)
    assert match, f"production function missing: {name}"
    return match[0] + "\n"


with tempfile.TemporaryDirectory(prefix="aegis-macos-digest-") as temporary:
    work = Path(temporary).resolve()
    key, public = work / "signing.key", work / "signing.pub"
    for args in (["openssl", "genpkey", "-algorithm", "ed25519", "-out", str(key)],
                 ["openssl", "pkey", "-in", str(key), "-pubout", "-out", str(public)]):
        result = command(args)
        assert result.returncode == 0, "fixture signing-key preparation failed"
    key.chmod(0o600)
    public.chmod(0o600)

    helpers = "".join(function(name) for name in (
        "verify_manifest_signature", "validate_release_policy", "release_floor_run",
        "download_url", "download_url_with_fallback"))
    # Relocate only floor destinations; actual signature/freshness/custody logic
    # remains intact even when this contract is run as root in Linux CI.
    for assignment in ('state_root="/Library/Application Support/Aegis/Install/releases"',
                       'state_root="/var/lib/aegis-install/releases"',
                       'state_root="${HOME}/.local/state/aegis-install/releases"'):
        assert helpers.count(assignment) == 1, "floor fixture seam changed"
        helpers = helpers.replace(assignment, 'state_root="${AEGIS_DIGEST_FIXTURE_FLOOR}"')
    helpers = helpers.replace("download_url() {", "actual_download_url() {", 1)
    helpers += '''
download_url() {
  case "$1" in
    *.tar.gz) printf 'archive\\n' >> "$AEGIS_DIGEST_FIXTURE_CALLS" ;;
    *.sha256) printf 'sibling\\n' >> "$AEGIS_DIGEST_FIXTURE_CALLS" ;;
    *) printf 'metadata\\n' >> "$AEGIS_DIGEST_FIXTURE_CALLS" ;;
  esac
  actual_download_url "$@"
}
'''
    begin = '  if ! download_url_with_fallback "${MAC_MANIFEST_PATH}" "${MANIFEST_URL_RESOLVED}"; then'
    end = '  tar --no-same-owner -xzf "${MAC_ARCHIVE_PATH}" -C "${MAC_EXTRACT_ROOT}"'
    assert source.count(begin) == source.count(end) == 1, "Mac production stage seam changed"
    start = source.index(begin)
    finish = source.index(end, start) + len(end)
    # Execute the exact source from signature admission through local extraction.
    # Stop before installer discovery/execution; no host installation is possible.
    stage = "set -euo pipefail\n" + helpers + source[start:finish] + "\n"
    count = 0

    def archive(path, payload):
        with tarfile.open(path, "w:gz") as output:
            member = tarfile.TarInfo("safe/marker")
            member.size = len(payload)
            output.addfile(member, io.BytesIO(payload))

    def check(arch, legacy, digest_kind):
        name = f"{arch}-{legacy}-{digest_kind}"
        case = work / name
        case.mkdir(mode=0o700)
        origin, staging, extracted = (case / leaf for leaf in ("origin", "staging", "extracted"))
        for directory in (origin, staging, extracted):
            directory.mkdir(mode=0o700)
        tarball = origin / f"aegis-client-0.0.0-macos-{arch}.tar.gz"
        archive(tarball, b"authenticated fixture bytes")
        good_digest = hashlib.sha256(tarball.read_bytes()).hexdigest()
        values = {"valid": good_digest, "tampered": good_digest, "null": None,
                  "number": 123, "array": [], "short": "f" * 63,
                  "nonhex": "g" * 64, "uppercase": "A" * 64,
                  "newline": good_digest + "\n"}
        selected = {} if digest_kind == "missing" else {"sha256": values[digest_kind]}
        other_arch = "aarch64" if arch == "x86_64" else "x86_64"
        now = int(time.time())
        manifest = {"version": "0.0.0", "channel": "rc", "prerelease": True,
                    "artifacts": {"macos_client": {"split": {
                        arch: selected, other_arch: {"sha256": good_digest}}}},
                    "release_policy": {"schema": "aegis_release_policy_v1",
                        "authority": "github:fixture/aegis:.github/workflows/release.yml",
                        "sequence": 1, "tag": "v0.0.0-rc.1",
                        "issued_at_unix": now - 10, "expires_at_unix": now + 3600}}
        manifest_path = origin / "release.manifest.json"
        manifest_path.write_text(json.dumps(manifest))
        result = command(["openssl", "pkeyutl", "-sign", "-inkey", str(key), "-rawin",
                          "-in", str(manifest_path), "-out", str(manifest_path) + ".sig"])
        assert result.returncode == 0, "fixture manifest signing failed"
        if digest_kind == "tampered":
            archive(tarball, b"substituted archive bytes")
        # A hostile mirror can always regenerate this unsigned sibling.
        Path(str(tarball) + ".sha256").write_text(
            hashlib.sha256(tarball.read_bytes()).hexdigest() + "  " + tarball.name + "\n")
        calls = case / "calls"
        calls.write_text("")
        result = command(["/bin/bash", "-c", stage], env={**os.environ,
            "AEGIS_MANIFEST_PUBKEY_PEM": str(public), "AEGIS_ALLOW_UNSIGNED_MANIFEST": legacy,
            "AEGIS_INSTALL_ALLOW_UNSIGNED": legacy, "MINIMUM_RELEASE_SEQUENCE": "1",
            "RELEASE_POLICY_AUTHORITY": "github:fixture/aegis:.github/workflows/release.yml",
            "REQUIRE_RELEASE_POLICY": "1", "ALLOW_HISTORICAL_POLICY": "0",
            "ROLE": "client", "OS_KIND": "macos", "AEGIS_HOST_ARCH": arch, "MAC_ARCH": arch,
            "OFFLINE": "1", "RELEASE_BASE": origin.as_uri(),
            "MANIFEST_URL_RESOLVED": manifest_path.as_uri(),
            "MAC_MANIFEST_PATH": str(staging / "release.manifest.json"),
            "MAC_ARCHIVE_PATH": str(staging / "archive.tar.gz"),
            "MAC_EXTRACT_ROOT": str(extracted), "AEGIS_DIGEST_FIXTURE_CALLS": str(calls),
            "AEGIS_DIGEST_FIXTURE_FLOOR": str(case / "floor")})
        assert "signature verified (ed25519 pinned key)" in result.stderr, (
            name, "actual signed-pair gate did not succeed", result.stderr)
        observed = calls.read_text().splitlines()
        assert "sibling" not in observed, f"{name}: unsigned sibling was consulted"
        marker = extracted / "safe/marker"
        if digest_kind == "valid":
            assert result.returncode == 0 and observed.count("archive") == 1, (name, result.stderr)
            assert marker.read_bytes() == b"authenticated fixture bytes", name
        else:
            assert result.returncode != 0 and not marker.exists(), (name, result.stderr)
            if digest_kind == "tampered":
                assert observed.count("archive") == 1 and "sha256 mismatch" in result.stderr, name
            else:
                assert observed.count("archive") == 0, f"{name}: invalid digest reached archive fetch"
                assert "signed manifest has no valid macOS archive digest" in result.stderr, name

    for arch in ("x86_64", "aarch64"):
        for legacy in ("0", "1"):
            for digest_kind in ("missing", "null", "number", "array", "short", "nonhex",
                                "uppercase", "newline", "tampered", "valid"):
                check(arch, legacy, digest_kind)
                count += 1
    print(f"PASS: {count} signed Mac digest cases; both arches/legacy flags, prefetch refusal, tampered sibling and valid extraction")
PY
