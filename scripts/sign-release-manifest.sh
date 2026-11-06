#!/usr/bin/env bash
# Sign a non-Windows release manifest from a private snapshot. Windows signed schemas 3/5
# releases require the bounded provenance-aware signer.
set -euo pipefail
manifest="${1:-}"
key="${AEGIS_MANIFEST_SIGNING_KEY:-}"
[[ -n "$manifest" && -f "$manifest" ]] || { echo "usage: AEGIS_MANIFEST_SIGNING_KEY=key.pem $0 MANIFEST" >&2; exit 2; }
[[ -n "$key" && -f "$key" && ! -L "$key" ]] || { echo 'FATAL: protected Ed25519 key unavailable' >&2; exit 3; }
signature="$manifest.sig"
[[ ! -e "$signature" ]] || { echo 'FATAL: signature output already exists' >&2; exit 4; }
private="$(mktemp -d "${RUNNER_TEMP:-/tmp}/aegis-manifest-sign.XXXXXXXX")"
chmod 700 "$private"
trap 'rm -rf -- "$private"' EXIT
python3 -I - "$manifest" "$private/manifest.json" <<'PY'
import os, pathlib, shutil, stat, sys
source, target = map(pathlib.Path, sys.argv[1:])
fd = os.open(source, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
st = os.fstat(fd)
if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1 or not 0 < st.st_size <= 65536:
    os.close(fd)
    raise SystemExit("unsafe manifest input")
with os.fdopen(fd, "rb") as src, target.open("xb") as dst:
    shutil.copyfileobj(src, dst); dst.flush(); os.fsync(dst.fileno())
PY
if python3 -I - "$private/manifest.json" <<'PY'
import json, pathlib, sys
m = json.loads(pathlib.Path(sys.argv[1]).read_bytes())
raise SystemExit(0 if m.get("platform") == "windows-x86_64" and m.get("schema") in (3,5) else 1)
PY
then
  echo 'FATAL: Windows manifests must use sign-windows-release-manifest.sh' >&2
  exit 4
fi
openssl pkeyutl -sign -inkey "$key" -rawin -in "$private/manifest.json" -out "$private/manifest.json.sig"
openssl pkey -in "$key" -pubout -out "$private/public.pem" 2>/dev/null
openssl pkeyutl -verify -pubin -inkey "$private/public.pem" -rawin -in "$private/manifest.json" -sigfile "$private/manifest.json.sig" >/dev/null
python3 -I - "$private/manifest.json.sig" "$signature" <<'PY'
import os, pathlib, shutil, sys
source, target = map(pathlib.Path, sys.argv[1:])
fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with source.open("rb") as src, os.fdopen(fd, "wb") as dst:
    shutil.copyfileobj(src, dst); dst.flush(); os.fsync(dst.fileno())
PY
echo "signed protected manifest snapshot: $signature"
