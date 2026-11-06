#!/usr/bin/env bash
# Генерация самоподписанного CA и сервера для локального теста Relay.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CERT_DIR="${ROOT}/certs"
mkdir -p "${CERT_DIR}"

if ! command -v openssl >/dev/null 2>&1; then
  echo "Нужен openssl в PATH" >&2
  exit 1
fi

openssl req -x509 -newkey rsa:2048 -days 3650 -nodes \
  -keyout "${CERT_DIR}/ca-key.pem" \
  -out "${CERT_DIR}/ca.pem" \
  -subj "/CN=AEGIS Dev CA"

openssl req -newkey rsa:2048 -nodes \
  -keyout "${CERT_DIR}/server-key.pem" \
  -out "${CERT_DIR}/server.csr" \
  -subj "/CN=localhost"

openssl x509 -req -in "${CERT_DIR}/server.csr" \
  -CA "${CERT_DIR}/ca.pem" -CAkey "${CERT_DIR}/ca-key.pem" -CAcreateserial \
  -out "${CERT_DIR}/server.pem" -days 825

rm -f "${CERT_DIR}/server.csr" "${CERT_DIR}/ca.srl"

echo "OK: ${CERT_DIR}/ca.pem (добавьте в relay.ca_cert клиента), ${CERT_DIR}/server.pem + server-key.pem для сервера"
