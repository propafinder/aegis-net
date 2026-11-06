#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"

if ! command -v openssl >/dev/null 2>&1; then
  echo "openssl is required" >&2
  exit 1
fi

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/aegis-relay-materials.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT

IP_CASE="${TMP_DIR}/ip-case"
DNS_CASE="${TMP_DIR}/dns-case"

# Standalone operator invocation must protect keys even with a permissive caller.
umask 022
"${ROOT}/scripts/generate-relay-materials.sh" "${IP_CASE}" "198.51.100.22" "198.51.100.22" >/dev/null
"${ROOT}/scripts/generate-relay-materials.sh" "${DNS_CASE}" "relay.example.org" "198.51.100.22" >/dev/null

python3 - "${IP_CASE}" "${DNS_CASE}" <<'PY'
import stat
import sys
from pathlib import Path

for directory in map(Path, sys.argv[1:]):
    for name, expected in (("ca-key.pem", 0o600), ("server-key.pem", 0o600),
                           ("ca.pem", 0o644), ("server.pem", 0o644)):
        metadata = (directory / name).lstat()
        assert stat.S_ISREG(metadata.st_mode), f"{name}: expected a regular file"
        assert stat.S_IMODE(metadata.st_mode) == expected, f"{name}: incorrect custody mode"
PY

IP_CERT_TEXT="${TMP_DIR}/ip-cert.txt"
DNS_CERT_TEXT="${TMP_DIR}/dns-cert.txt"

openssl x509 -in "${IP_CASE}/server.pem" -noout -text >"${IP_CERT_TEXT}"
openssl x509 -in "${DNS_CASE}/server.pem" -noout -text >"${DNS_CERT_TEXT}"

grep -Fq -- "IP Address:198.51.100.22" "${IP_CERT_TEXT}"
grep -Fq -- "DNS:relay.example.org" "${DNS_CERT_TEXT}"
grep -Fq -- "IP Address:198.51.100.22" "${DNS_CERT_TEXT}"

# Issuance must remain valid and keep the same leaf public-key bootstrap pin.
for cert_dir in "${IP_CASE}" "${DNS_CASE}"; do
  openssl verify -CAfile "${cert_dir}/ca.pem" "${cert_dir}/server.pem" >/dev/null
  EXPECTED_PIN="$(openssl x509 -pubkey -noout -in "${cert_dir}/server.pem" \
    | openssl pkey -pubin -outform der \
    | openssl dgst -sha256 -binary | base64 | tr -d '\n')"
  [[ "$(cat "${cert_dir}/server.spki.b64")" == "${EXPECTED_PIN}" ]]
done

echo "VALIDITY: chain, SAN, custody and SPKI controls passed"

# The issuer may identify this deployment, but must not add a product-wide tag.
python3 - "${IP_CASE}" "198.51.100.22" "${DNS_CASE}" "relay.example.org" <<'PY_CA'
import subprocess
import sys
from pathlib import Path

for index in (1, 3):
    directory = Path(sys.argv[index])
    identity = sys.argv[index + 1]
    def distinguished_name(filename, field):
        result = subprocess.run(["openssl", "x509", "-in", str(directory / filename),
                                 "-noout", "-" + field, "-nameopt", "RFC2253"],
                                check=True, capture_output=True, text=True, timeout=5)
        return result.stdout.strip().split("=", 1)[1].strip()
    subject = distinguished_name("ca.pem", "subject")
    issuer = distinguished_name("server.pem", "issuer")
    assert issuer == subject, "leaf issuer must retain the generated trust chain"
    assert subject == "CN=" + identity, "CA subject must use the existing deployment identity"
print("PASS: deployment-specific CA subject")
PY_CA

echo "PASS: relay materials contract"
