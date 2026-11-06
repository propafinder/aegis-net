#!/usr/bin/env python3
import argparse, hashlib, json, os, pathlib, re, stat, zipfile

def regular(path: pathlib.Path, limit: int) -> bytes:
    st = path.lstat()
    if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1 or not 0 < st.st_size <= limit:
        raise SystemExit(f"invalid bounded regular file: {path}")
    return path.read_bytes()

p = argparse.ArgumentParser()
p.add_argument("--manifest", required=True, type=pathlib.Path)
p.add_argument("--archive", required=True, type=pathlib.Path)
p.add_argument("--handoff", required=True, type=pathlib.Path)
p.add_argument("--expected-source", required=True)
p.add_argument("--expected-workflow", required=True)
p.add_argument("--expected-ref", required=True)
p.add_argument("--expected-inner-zip-sha256", required=True)
p.add_argument("--expected-github-artifact-digest", required=True)
p.add_argument("--provenance-output", required=True, type=pathlib.Path)
a = p.parse_args()
if not re.fullmatch(r"[0-9a-f]{40}", a.expected_source) or not re.fullmatch(r"[0-9a-f]{64}", a.expected_inner_zip_sha256):
    raise SystemExit("trusted source or inner ZIP digest malformed")
if a.expected_github_artifact_digest != "not-used" and not re.fullmatch(r"[0-9a-f]{64}", a.expected_github_artifact_digest):
    raise SystemExit("trusted GitHub artifact-service digest malformed")
if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+:.+", a.expected_workflow) or not re.fullmatch(r"refs/(heads|tags)/[A-Za-z0-9._/-]+", a.expected_ref):
    raise SystemExit("trusted workflow or ref malformed")
manifest_raw = regular(a.manifest, 65536)
archive_raw = regular(a.archive, 1024 * 1024 * 1024)
handoff = json.loads(regular(a.handoff, 65536), object_pairs_hook=lambda pairs: dict(pairs) if len(pairs) == len(dict(pairs)) else (_ for _ in ()).throw(ValueError("duplicate key")))
manifest = json.loads(manifest_raw, object_pairs_hook=lambda pairs: dict(pairs) if len(pairs) == len(dict(pairs)) else (_ for _ in ()).throw(ValueError("duplicate key")))
manifest_fields = {"schema", "platform", "source_commit", "signed_release", "authenticode", "files"}
project_licenses = False
if isinstance(manifest, dict) and "project_licenses" in manifest:
    if type(manifest["project_licenses"]) is not bool:
        raise SystemExit("project license declaration must be boolean")
    project_licenses = manifest["project_licenses"]
    manifest_fields.add("project_licenses")
if project_licenses and set(manifest) != manifest_fields:
    raise SystemExit("manifest schema fields rejected")
archive_hash = hashlib.sha256(archive_raw).hexdigest()
if archive_hash != a.expected_inner_zip_sha256:
    raise SystemExit("archive does not match trusted inner ZIP digest")
if set(handoff) != {"schema", "source_commit", "workflow", "ref", "archive", "archive_sha256", "manifest_sha256", "signed_release", "manifest_signature_status"}:
    raise SystemExit("manifest signing handoff schema rejected")
if not (handoff.get("schema") == "aegis_windows_authenticode_handoff_v1" and
        handoff.get("source_commit") == a.expected_source == manifest.get("source_commit") and
        handoff.get("workflow") == a.expected_workflow and handoff.get("ref") == a.expected_ref and
        handoff.get("archive") == a.archive.name and
        handoff.get("archive_sha256") == archive_hash and
        handoff.get("manifest_sha256") == hashlib.sha256(manifest_raw).hexdigest() and
        handoff.get("signed_release") is False and
        handoff.get("manifest_signature_status") == "required_external_sidecar" and
        manifest.get("schema") in (3,5) and manifest.get("signed_release") is True):
    raise SystemExit("manifest signing handoff identity rejected")
expected = ["README.txt", "WINTUN-LICENSE.txt", "aegis-client.exe", "aegis-winctl.exe", "manifest.json", "wintun.dll"]
if manifest["schema"] == 5:
    expected += ["aegis-measure.exe", "aegis-transport-lab.exe", "research-operators.json"]
license_names = ("LICENSE-MIT", "LICENSE-APACHE", "NOTICE")
if project_licenses:
    expected += list(license_names)
    if not isinstance(manifest["files"], dict) or set(manifest["files"]) != set(expected) - {"manifest.json"}:
        raise SystemExit("licensed manifest payload inventory rejected")
    for name in license_names:
        digest = manifest["files"][name]
        if not isinstance(digest, str) or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
            raise SystemExit("project license manifest digest rejected")
with zipfile.ZipFile(a.archive) as z:
    if sorted(z.namelist()) != sorted(expected) or z.read("manifest.json") != manifest_raw:
        raise SystemExit("archive/manifest mix or unexpected ZIP file set")
    if project_licenses:
        for name in license_names:
            info = z.getinfo(name)
            mode = stat.S_IFMT(info.external_attr >> 16)
            if info.is_dir() or mode not in (0, stat.S_IFREG) or not 0 < info.file_size <= 2 * 1024 * 1024:
                raise SystemExit("project license ZIP entry rejected")
            if hashlib.sha256(z.read(name)).hexdigest() != manifest["files"][name]:
                raise SystemExit("project license ZIP digest mismatch")
provenance = {
    "schema": "aegis_windows_release_provenance_v1",
    "source_commit": a.expected_source,
    "workflow": a.expected_workflow,
    "ref": a.expected_ref,
    "manifest_sha256": hashlib.sha256(manifest_raw).hexdigest(),
    "inner_zip_sha256": archive_hash,
    "github_artifact_digest": a.expected_github_artifact_digest,
}
raw = (json.dumps(provenance, sort_keys=True, indent=2, separators=(",", ": ")) + "\n").encode()
fd = os.open(a.provenance_output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(fd, "wb") as out:
    out.write(raw); out.flush(); os.fsync(out.fileno())
print("bounded Windows manifest signing handoff: PASS")
