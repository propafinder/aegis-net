#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/aegis-opsec-gate.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT

printf 'ordinary release artifact\n' >"${TMP_DIR}/clean.bin"
printf 'artifact contains forbidden-region-word\n' >"${TMP_DIR}/dirty.bin"

bash "${ROOT}/scripts/release-opsec-gate.sh" \
  --input "${TMP_DIR}/clean.bin" \
  --pattern forbidden-region-word \
  --output-json "${TMP_DIR}/clean.json"

if bash "${ROOT}/scripts/release-opsec-gate.sh" \
  --input "${TMP_DIR}/dirty.bin" \
  --pattern forbidden-region-word \
  --output-json "${TMP_DIR}/dirty.json"; then
  echo "expected dirty artifact to fail opsec gate" >&2
  exit 1
fi

grep -q '"event": "release_opsec_gate"' "${TMP_DIR}/clean.json"
grep -q '"status": "PASS"' "${TMP_DIR}/clean.json"
grep -Fq '"hits": [' "${TMP_DIR}/clean.json"
grep -q '"status": "FAIL"' "${TMP_DIR}/dirty.json"
grep -q '"pattern": "forbidden-region-word"' "${TMP_DIR}/dirty.json"

# Exercise the actual compressed public-artifact path; scanning only raw gzip
# bytes must not count as inspecting the embedded executable/configuration.
python3 - "${TMP_DIR}" <<'PY'
import gzip, io, tarfile, sys
from pathlib import Path
root=Path(sys.argv[1])
for name, member, body in [('clean','bin/client',b'ordinary release artifact\n'),
                           ('dirty','bin/client',b'forbidden-region-word\n'),
                           ('unsafe','../outside',b'ordinary release artifact\n')]:
    with tarfile.open(root/(name+'.tar.gz'),'w:gz') as archive:
        entry=tarfile.TarInfo(member); entry.size=len(body); archive.addfile(entry,io.BytesIO(body))
assert b'forbidden-region-word' not in (root/'dirty.tar.gz').read_bytes(), 'fixture must hide the marker under compression'
(root/'broken.tar.gz').write_bytes(b'not gzip')
(root/'empty').mkdir()
(root/'linked').symlink_to(root/'clean.bin')
# Reserved documentation literals are not fleet disclosures.
(root/'documentation.bin').write_text('192.0.2.1 198.51.100.42 203.0.113.7\n')
PY
bash "${ROOT}/scripts/release-opsec-gate.sh" --input "${TMP_DIR}/clean.tar.gz" --pattern forbidden-region-word --output-json "${TMP_DIR}/archive-clean.json"
bash "${ROOT}/scripts/release-opsec-gate.sh" --input "${TMP_DIR}/documentation.bin" --pattern forbidden-region-word --output-json "${TMP_DIR}/documentation.json"
for input in dirty.tar.gz unsafe.tar.gz broken.tar.gz empty linked; do
  if bash "${ROOT}/scripts/release-opsec-gate.sh" --input "${TMP_DIR}/${input}" --pattern forbidden-region-word --output-json "${TMP_DIR}/rejected-${input}.json"; then
    echo "expected rejected opsec fixture: ${input}" >&2
    exit 1
  fi
done
grep -q '"source": "archive_bytes"' "${TMP_DIR}/rejected-dirty.tar.gz.json"

echo "PASS: release opsec gate contract"
