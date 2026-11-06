#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/aegis-fronted-bundle.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT

SECRET_READER="${AEGIS_TEST_SECRET_READER:-${ROOT}/target/debug/aegis-server}"
[[ "$SECRET_READER" == /* && -x "$SECRET_READER" ]] || { echo "Actual Rust reader required." >&2; exit 2; }

CONFIG="${TMP_DIR}/aegis-server.toml"
CA="${TMP_DIR}/system-ca.pem"
MASQUE_CA="${TMP_DIR}/masque-ca.pem"
OUT="${TMP_DIR}/client-bundle-fronted.tar.gz"
EXTRACT="${TMP_DIR}/extract"

printf '%s\n' 'auth_token = "contract-secret"' > "${CONFIG}"
printf '%s\n' '-----BEGIN CERTIFICATE-----' 'contract' '-----END CERTIFICATE-----' > "${CA}"
printf '%s\n' '-----BEGIN CERTIFICATE-----' 'masque-contract' '-----END CERTIFICATE-----' > "${MASQUE_CA}"

bash "${ROOT}/scripts/issue-fronted-bundle.sh" \
  --server-bin "$SECRET_READER" --config "${CONFIG}" \
  --primary primary.example.test \
  --failover failover-a.example.test \
  --failover failover-b.example.test:8443 \
  --ca "${CA}" \
  --masque-ca "${MASQUE_CA}" \
  --out "${OUT}" >/dev/null

mkdir -p "${EXTRACT}"
tar -xzf "${OUT}" -C "${EXTRACT}"
CFG="$(find "${EXTRACT}" -name aegis-client.toml -type f -print -quit)"
[[ -n "${CFG}" ]]
[[ -f "$(dirname "${CFG}")/masque-ca.pem" ]]
grep -Fq 'masque-contract' "$(dirname "${CFG}")/masque-ca.pem"
for name in aegis-client.toml aegis-client-privileged-dns.toml; do
  grep -Fq 'masque_ca_cert = "masque-ca.pem"' "$(dirname "${CFG}")/${name}"
done
cmp -s "${CA}" "$(dirname "${CFG}")/ca.pem"
cmp -s "${MASQUE_CA}" "$(dirname "${CFG}")/masque-ca.pem"

grep -Fq 'server = "primary.example.test:443"' "${CFG}"
grep -Fq 'transport_priority = ["grpc_stream"]' "${CFG}"

primary_line="$(grep -nF '{ server = "primary.example.test:443", server_name = "primary.example.test" }' "${CFG}" | cut -d: -f1)"
failover_a_line="$(grep -nF '{ server = "failover-a.example.test:443", server_name = "failover-a.example.test" }' "${CFG}" | cut -d: -f1)"
failover_b_line="$(grep -nF '{ server = "failover-b.example.test:8443", server_name = "failover-b.example.test" }' "${CFG}" | cut -d: -f1)"

[[ "${primary_line}" -lt "${failover_a_line}" ]]
[[ "${failover_a_line}" -lt "${failover_b_line}" ]]

# Exercise the real producer and Rust secret reader for both SocketAddr
# families. No failover is needed to retain the primary's direct UDP leg.
for socket in '203.0.113.9:8443' '[2001:db8::9]:8443'; do
  bash "${ROOT}/scripts/issue-fronted-bundle.sh" \
    --server-bin "$SECRET_READER" --config "${CONFIG}" \
    --primary primary.example.test --ca "${CA}" --masque-ca "${MASQUE_CA}" \
    --masque-server "${socket}" --transport-priority grpc_stream,masque_derived \
    --out "${TMP_DIR}/direct.tar.gz" >"${TMP_DIR}/direct.log" 2>&1
  if grep -Fq -- "${socket}" "${TMP_DIR}/direct.log"; then
    echo "direct MASQUE origin leaked to producer output" >&2; exit 1
  fi
  python3 -I -B - "${TMP_DIR}/direct.tar.gz" "${socket}" "${CA}" "${MASQUE_CA}" <<'PY'
import pathlib, sys, tarfile, tomllib
archive, socket, edge, origin = sys.argv[1:]
with tarfile.open(archive) as bundle:
    prefix = 'client-bundle/'
    assert bundle.extractfile(prefix+'ca.pem').read() == pathlib.Path(edge).read_bytes()
    assert bundle.extractfile(prefix+'masque-ca.pem').read() == pathlib.Path(origin).read_bytes()
    for leaf in ('aegis-client.toml', 'aegis-client-privileged-dns.toml'):
        relay = tomllib.loads(bundle.extractfile(prefix+leaf).read().decode())['relay']
        assert relay['server'] == 'primary.example.test:443'
        assert relay['server_name'] == 'primary.example.test'
        assert relay['endpoints'] == [dict(server=relay['server'],
            server_name=relay['server_name'], masque_server=socket)]
        assert relay['transport_priority'] == ['grpc_stream', 'masque_derived']
        assert relay['ca_cert'] == '__CLIENT_CA_CERT_PATH__'
        assert relay['masque_ca_cert'] == 'masque-ca.pem'
PY
done
for socket in 'relay.example.test:8443' '203.0.113.9:0' '203.0.113.9:65536' \
              '203.0.113.9:08443' '2001:db8::9:8443' '[fe80::9%eth0]:8443' \
              '203.0.113.9:8443;other,authority'; do
  if bash "${ROOT}/scripts/issue-fronted-bundle.sh" \
      --server-bin "$SECRET_READER" --config "${CONFIG}" \
      --primary primary.example.test --ca "${CA}" --masque-server "${socket}" \
      --out "${TMP_DIR}/invalid.tar.gz" >"${TMP_DIR}/invalid.log" 2>&1; then
    echo "invalid direct MASQUE address accepted" >&2; exit 1
  fi
  [[ ! -e "${TMP_DIR}/invalid.tar.gz" ]]
  grep -Fq -- '--masque-server requires a literal IP and port 1..65535' "${TMP_DIR}/invalid.log"
done

if grep -Fq 'contract-secret' <(bash "${ROOT}/scripts/issue-fronted-bundle.sh" \
  --server-bin "$SECRET_READER" --config "${CONFIG}" --primary primary.example.test --ca "${CA}" \
  --out "${TMP_DIR}/second.tar.gz" 2>&1); then
  echo "fronted bundle helper leaked relay auth token" >&2
  exit 1
fi

echo "PASS: fronted bundle keeps primary, numeric UDP endpoint, separate trust and private token"
