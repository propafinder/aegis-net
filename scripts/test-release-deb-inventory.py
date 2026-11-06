#!/usr/bin/env python3
"""Self-contained DEB inventory regression contract for a clean checkout."""

import hashlib
import io
import json
import lzma
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile

ROOT = Path(__file__).resolve().parents[1]
VERIFIER = Path(__file__).with_name("verify-release-deb-inventory.py")
SOURCE_SHA = "a" * 40
VERSION = "0.3.50"


def tar_xz(name, content, uid=0):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        member = tarfile.TarInfo(name)
        member.uid = member.gid = uid
        member.size = len(content)
        archive.addfile(member, io.BytesIO(content))
    return lzma.compress(stream.getvalue())


def ar_member(name, content):
    header = (f"{name}/".ljust(16) + "0".ljust(12) + "0".ljust(6) +
              "0".ljust(6) + "100644".ljust(8) + str(len(content)).ljust(10) + "`\n").encode("ascii")
    assert len(header) == 60
    return header + content + (b"\n" if len(content) % 2 else b"")


def deb_bytes(package, arch, data_uid=0):
    control = f"Package: {package}\nVersion: {VERSION}\nArchitecture: {arch}\n".encode()
    return (b"!<arch>\n" + ar_member("debian-binary", b"2.0\n") +
            ar_member("control.tar.xz", tar_xz("control", control)) +
            ar_member("data.tar.xz", tar_xz("usr/local/bin/aegis-probe", b"fixture", data_uid)))


def write_json(path, value):
    path.write_text(json.dumps(value, sort_keys=True) + "\n", encoding="utf-8")


def fixture(root):
    root.mkdir()
    (root / "INSTALL.md").write_text("offline fixture instructions\n")
    for arch, deb_arch, name, marker in (
        ("x86_64", "amd64", "release.manifest.json", "split-deb-packages.manifest.json"),
        ("aarch64", "arm64", "release.manifest-aarch64.json", "split-deb-packages-aarch64.manifest.json"),
    ):
        records = {}
        packages = {}
        for role in ("server", "client", "combined"):
            package = "aegis" if role == "combined" else f"aegis-{role}"
            basename = f"{package}_{VERSION}_{deb_arch}.deb"
            body = deb_bytes(package, deb_arch)
            (root / basename).write_bytes(body)
            digest = hashlib.sha256(body).hexdigest()
            (root / f"{basename}.sha256").write_text(f"{digest}  {basename}\n")
            records[role] = {"path": basename, "sha256_path": f"{basename}.sha256", "sha256": digest}
            if role != "combined":
                packages[package] = {"deb_file": basename}
        write_json(root / marker, {"version": VERSION, "deb_arch": deb_arch, "packages": packages})
        write_json(root / name, {"schema": "aegis_linux_release_manifest_v1", "git_sha": SOURCE_SHA,
                                 "version": VERSION, "arch": arch, "artifacts": {"deb": {
                                     "status": "ready", "manifest_path": marker,
                                     "split": {"server": records["server"], "client": records["client"]},
                                     "combined": records["combined"]}}})


def run(root, expected, phrase="", seal=False, github_output=None, split_checker=None,
        signature_mode="unsigned", public_key=None):
    cmd = (sys.executable, "-I", "-B", str(VERIFIER), str(root), "--source-sha", SOURCE_SHA)
    if seal:
        cmd += ("--seal-markers",)
    if github_output is not None:
        cmd += ("--github-output", str(github_output))
    if split_checker is not None:
        cmd += ("--split-checker", str(split_checker))
    cmd += ("--signature-mode", signature_mode)
    if public_key is not None:
        cmd += ("--public-key", str(public_key))
    result = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, timeout=90)
    output = result.stdout + result.stderr
    assert (result.returncode == 0) is expected and phrase in output, (result.returncode, output)
    print("PASS" if expected else "REFUSED", phrase or ("sealed fixture" if seal else "consumer rehash"))


def copy_fixture(source, target):
    shutil.copytree(source, target)


def main():
    pinned = Path(__file__).with_name("release-ed25519-public.pem").read_text()
    workflow = (ROOT / ".github/workflows/release.yml").read_text()
    key_line = pinned.splitlines()[1]
    assert key_line in workflow, "consumer release key differs from signer pin"
    with tempfile.TemporaryDirectory(prefix="aegis-b03-inventory-", dir=Path(__file__).parent) as temporary:
        work = Path(temporary)
        baseline = work / "baseline"
        fixture(baseline)
        run(baseline, False, "split marker digest mismatch")
        run(baseline, True, seal=True)
        output = work / "github-output"
        output.touch()
        run(baseline, True, github_output=output)
        lines = output.read_text().splitlines()
        assert lines[0].startswith("upload_paths<<") and lines[-1] == lines[0].split("<<", 1)[1]
        pinned = tuple(Path(line) for line in lines[1:-1])
        assert len(pinned) == 18 and set(pinned) == set(baseline.iterdir())
        (baseline / "late_0.3.50_amd64.deb").write_bytes(b"added after snapshot")
        assert all(path.name != "late_0.3.50_amd64.deb" for path in pinned)
        transferred = work / "transferred"
        transferred.mkdir()
        for path in pinned:
            shutil.copyfile(path, transferred / path.name)
        run(transferred, True)
        with (transferred / f"aegis_{VERSION}_amd64.deb").open("ab") as stream:
            stream.write(b"changed after upload")
        run(transferred, False, "SHA or sidecar mismatch")
        (transferred / f"aegis_{VERSION}_amd64.deb").write_bytes((baseline / f"aegis_{VERSION}_amd64.deb").read_bytes())
        (transferred / "INSTALL.md").write_text("changed after upload\n")
        run(transferred, False, "release payload byte mismatch")
        (baseline / "late_0.3.50_amd64.deb").unlink()
        raced = work / "raced"
        copy_fixture(baseline, raced)
        wrapper = work / "split-wrapper.py"
        checker = ROOT / "scripts/verify-split-deb-package-set.py"
        wrapper.write_text("import pathlib, subprocess, sys\n"
                           f"result = subprocess.run([sys.executable, '-I', '-B', {str(checker)!r}, *sys.argv[1:]])\n"
                           "if result.returncode: raise SystemExit(result.returncode)\n"
                           "if sys.argv[sys.argv.index('--arch') + 1] == 'arm64':\n"
                           "    (pathlib.Path(sys.argv[1]) / 'late_0.3.50_arm64.deb').write_bytes(b'late')\n")
        raced_output = work / "raced-output"
        raced_output.touch()
        run(raced, True, github_output=raced_output, split_checker=wrapper)
        raced_lines = raced_output.read_text().splitlines()
        assert (raced / "late_0.3.50_arm64.deb").exists()
        assert all("late_0.3.50_arm64.deb" not in line for line in raced_lines)
        raced_transfer = work / "raced-transfer"
        raced_transfer.mkdir()
        for name in raced_lines[1:-1]:
            file = Path(name)
            shutil.copyfile(file, raced_transfer / file.name)
        run(raced_transfer, True)
        forged_unsigned = work / "forged-unsigned"
        copy_fixture(baseline, forged_unsigned)
        (forged_unsigned / "release.manifest.json.sig").write_bytes(b"\0" * 64)
        run(forged_unsigned, False, "unsigned handoff contains release signatures")
        signed = work / "signed"
        copy_fixture(baseline, signed)
        for name in ("client-release.manifest.json", "client-release.manifest-aarch64.json"):
            write_json(signed / name, {"schema": "fixture_client_release_v1"})
        secret_key, public_key = work / "test-ed25519.key", work / "test-ed25519.pub"
        subprocess.run(("openssl", "genpkey", "-algorithm", "ED25519", "-out", str(secret_key)),
                       check=True, capture_output=True, timeout=15)
        subprocess.run(("openssl", "pkey", "-in", str(secret_key), "-pubout", "-out", str(public_key)),
                       check=True, capture_output=True, timeout=15)
        for name in ("release.manifest.json", "release.manifest-aarch64.json",
                     "client-release.manifest.json", "client-release.manifest-aarch64.json"):
            subprocess.run(("openssl", "pkeyutl", "-sign", "-inkey", str(secret_key),
                            "-rawin", "-in", str(signed / name), "-out", str(signed / f"{name}.sig")),
                           check=True, capture_output=True, timeout=15)
        run(signed, True, signature_mode="signed", public_key=public_key)
        bad_signature = signed / "release.manifest.json.sig"
        old_signature = bad_signature.read_bytes()
        bad_signature.write_bytes(b"\0" * 64)
        run(signed, False, "release signature refused", signature_mode="signed", public_key=public_key)
        bad_signature.write_bytes(old_signature)
        (signed / "client-release.manifest.json").write_text("changed after signing\n")
        run(signed, False, "release signature refused", signature_mode="signed", public_key=public_key)
        extra = work / "extra"
        copy_fixture(baseline, extra)
        (extra / "extra_0.3.50_arm64.deb").write_bytes(b"late swap")
        run(extra, False, "extra or missing DEB inventory files")
        marker = work / "marker"
        copy_fixture(baseline, marker)
        with (marker / "split-deb-packages-aarch64.manifest.json").open("ab") as stream:
            stream.write(b" ")
        run(marker, False, "split marker digest mismatch")
        altered = work / "altered"
        copy_fixture(baseline, altered)
        with (altered / f"aegis_{VERSION}_amd64.deb").open("ab") as stream:
            stream.write(b"tamper")
        run(altered, False, "SHA or sidecar mismatch")
        owner = work / "owner"
        copy_fixture(baseline, owner)
        bad_name = f"aegis_{VERSION}_amd64.deb"
        body = deb_bytes("aegis", "amd64", data_uid=1)
        (owner / bad_name).write_bytes(body)
        digest = hashlib.sha256(body).hexdigest()
        (owner / f"{bad_name}.sha256").write_text(f"{digest}  {bad_name}\n")
        manifest = owner / "release.manifest.json"
        data = json.loads(manifest.read_text())
        data["artifacts"]["deb"]["combined"]["sha256"] = digest
        write_json(manifest, data)
        run(owner, False, "combined DEB owner refused")
        changed = work / "changed"
        copy_fixture(baseline, changed)
        manifest = changed / "release.manifest-aarch64.json"
        data = json.loads(manifest.read_text())
        data["version"] = "0.3.51"
        write_json(manifest, data)
        run(changed, False, "version mismatch")
        linked = work / "linked"
        copy_fixture(baseline, linked)
        archive = linked / f"aegis_{VERSION}_arm64.deb"
        archive.rename(linked / "renamed")
        archive.symlink_to(linked / "renamed")
        run(linked, False, "release symlink")
        nested = work / "nested"
        copy_fixture(baseline, nested)
        (nested / "hidden").mkdir()
        run(nested, False, "nonflat release entry")
        huge = work / "huge"
        copy_fixture(baseline, huge)
        for index in range(239):
            (huge / f"pad-{index:03}").touch()
        run(huge, False, "more than 256 flat regular files")
        duplicate = work / "duplicate"
        copy_fixture(baseline, duplicate)
        marker_path = duplicate / "split-deb-packages.manifest.json"
        marker_path.write_text(marker_path.read_text().replace('"version":', '"version": "0.3.50", "version":', 1))
        run(duplicate, False, "duplicate JSON key")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
