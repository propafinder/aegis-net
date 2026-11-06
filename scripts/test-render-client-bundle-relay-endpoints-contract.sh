#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/aegis-render-client-bundle-endpoints.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT

SECRET_READER="${AEGIS_TEST_SECRET_READER:-${ROOT}/target/debug/aegis-server}"
[[ "$SECRET_READER" == /* && -x "$SECRET_READER" ]] || { echo "Actual compiled Rust secret reader required." >&2; exit 2; }
[[ "$("$SECRET_READER" installer-secret version)" == installer-secret-v1 ]] || exit 2

CA_CERT="${TMP_DIR}/ca.pem"
BUNDLE_DIR="${TMP_DIR}/client-bundle"
printf '%s\n' '-----BEGIN CERTIFICATE-----' 'contract' '-----END CERTIFICATE-----' > "${CA_CERT}"

printf '%s' 'contract-token' | bash "${ROOT}/scripts/render-client-bundle.sh" \
  "${BUNDLE_DIR}" \
  "relay-a.example.org:443" \
  "relay-a.example.org" \
  --auth-token-stdin \
  "${CA_CERT}" \
  "$SECRET_READER" \
  "relay-a.example.org:443,relay-a.example.org;relay-b.example.org:443,relay-b.example.org,relay-b.example.org:443" \
  "https_ws,grpc_stream"

for cfg in "${BUNDLE_DIR}/aegis-client.toml" "${BUNDLE_DIR}/aegis-client-privileged-dns.toml"; do
  grep -q 'server = "relay-a.example.org:443"' "${cfg}"
  grep -q 'server_name = "relay-a.example.org"' "${cfg}"
  grep -q 'endpoints = \[' "${cfg}"
  grep -q '{ server = "relay-a.example.org:443", server_name = "relay-a.example.org" }' "${cfg}"
  grep -q '{ server = "relay-b.example.org:443", server_name = "relay-b.example.org", masque_server = "relay-b.example.org:443" }' "${cfg}"
  grep -Fq 'transport_priority = ["https_ws", "grpc_stream"]' "${cfg}"
done

if printf '%s' 'contract-token' | bash "${ROOT}/scripts/render-client-bundle.sh" \
  "${TMP_DIR}/bad-bundle" \
  "relay-a.example.org:443" \
  "relay-a.example.org" \
  --auth-token-stdin \
  "${CA_CERT}" \
  "$SECRET_READER" \
  "relay-a.example.org:443"; then
  echo "expected invalid endpoint entry to fail" >&2
  exit 1
fi

if printf '%s' 'contract-token' | bash "${ROOT}/scripts/render-client-bundle.sh" \
  "${TMP_DIR}/bad-priority-bundle" \
  "relay-a.example.org:443" \
  "relay-a.example.org" \
  --auth-token-stdin \
  "${CA_CERT}" \
  "$SECRET_READER" \
  "" \
  "https_ws,bad_transport"; then
  echo "expected invalid transport priority to fail" >&2
  exit 1
fi

echo "ok"
