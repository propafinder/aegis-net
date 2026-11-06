#!/usr/bin/env bash
set -euo pipefail
if [[ $# -ne 9 ]]; then
  echo "usage: $0 MANIFEST ARCHIVE HANDOFF SIDECAR_DIRECTORY EXPECTED_SOURCE EXPECTED_WORKFLOW EXPECTED_REF EXPECTED_INNER_ZIP_SHA256 EXPECTED_GITHUB_ARTIFACT_DIGEST" >&2
  exit 2
fi
repo="$(cd "$(dirname "$0")/.." && pwd)"
key="${AEGIS_MANIFEST_SIGNING_KEY:?protected Ed25519 key path required}"
[[ -f "$key" && ! -L "$key" ]] || { echo 'protected Ed25519 key unavailable' >&2; exit 3; }
[[ -d "$4" && ! -L "$4" ]] || { echo 'external sidecar directory unavailable' >&2; exit 3; }
manifest_sig="$4/manifest.json.sig"
provenance="$4/windows-release.provenance.json"
provenance_sig="$provenance.sig"
for output in "$manifest_sig" "$provenance" "$provenance_sig"; do
  [[ ! -e "$output" ]] || { echo "protected signer output already exists: $output" >&2; exit 4; }
done
private="$(mktemp -d "${RUNNER_TEMP:-/tmp}/aegis-manifest-sign.XXXXXXXX")"
chmod 700 "$private"
trap 'rm -rf -- "$private"' EXIT
archive_name="${2##*/}"
[[ "$archive_name" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*\.zip$ ]] || { echo 'unsafe inner ZIP basename' >&2; exit 4; }
python3 -I - "$private" "$archive_name" "$1" "$2" "$3" <<'PY'
import os, pathlib, shutil, stat, sys
root = pathlib.Path(sys.argv[1])
archive_name = sys.argv[2]
for source, name, limit in zip(map(pathlib.Path, sys.argv[3:]), ("manifest.json", archive_name, "handoff.json"), (65536, 1 << 30, 65536)):
    fd = os.open(source, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    st = os.fstat(fd)
    if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1 or not 0 < st.st_size <= limit:
        os.close(fd)
        raise SystemExit(f"unsafe signer input: {source}")
    target = root / name
    with os.fdopen(fd, "rb") as src, target.open("xb") as dst:
        shutil.copyfileobj(src, dst, 1024 * 1024)
        dst.flush(); os.fsync(dst.fileno())
PY
python3 -I "$repo/scripts/verify-windows-manifest-signing-handoff.py" \
  --manifest "$private/manifest.json" --archive "$private/$archive_name" --handoff "$private/handoff.json" \
  --expected-source "$5" --expected-workflow "$6" --expected-ref "$7" \
  --expected-inner-zip-sha256 "$8" --expected-github-artifact-digest "$9" \
  --provenance-output "$private/windows-release.provenance.json"
cat > "$private/pinned.pem" <<'PUBKEY'
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEA6T0PK4ao6847zmnihkPAI3sRIvhuBTfw4GDX04rZ4m0=
-----END PUBLIC KEY-----
PUBKEY
openssl pkey -in "$key" -pubout -out "$private/provider.pem" 2>/dev/null
cmp "$private/pinned.pem" "$private/provider.pem"
for input in manifest.json windows-release.provenance.json; do
  openssl pkeyutl -sign -inkey "$key" -rawin -in "$private/$input" -out "$private/$input.sig"
  openssl pkeyutl -verify -pubin -inkey "$private/pinned.pem" -rawin -in "$private/$input" -sigfile "$private/$input.sig" >/dev/null
done
python3 -I - "$private/manifest.json.sig" "$manifest_sig" "$private/windows-release.provenance.json" "$provenance" "$private/windows-release.provenance.json.sig" "$provenance_sig" <<'PY'
import os, pathlib, shutil, sys
for source, target in zip(map(pathlib.Path, sys.argv[1::2]), map(pathlib.Path, sys.argv[2::2])):
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with source.open("rb") as src, os.fdopen(fd, "wb") as dst:
        shutil.copyfileobj(src, dst); dst.flush(); os.fsync(dst.fileno())
PY
echo "signed protected Windows manifest and provenance envelope"
